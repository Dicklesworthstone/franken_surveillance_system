# Owner-approved recording cleanup by age and source-byte target

`fss-event delete retention-plan` selects an exact cohort of completed file imports for one
sensor. `retention-commit` executes one sealed union-closure deletion under its exact approval,
using the existing tombstone-first, local unlink, verification and completion protocol.

An optional source-byte target selects the oldest safe age-eligible imports first. The default
remains cleanup of every safely deletable expired import.

This implements one-shot cleanup, not a standing retention policy, daemon, automatic
hold release, or remote archive deletion. The policy-change work packages remain open. It is a
reference implementation, **not production-qualified**. The source-byte additions have passed
source review and pinned formatting. Native compilation and execution remain blocked by a
compiler SIGKILL in unchanged Asupersync; the presence of executable checks is not proof that
they passed.

## Preview before any deletion

Supply the exact sensor identity, a positive retention duration in nanoseconds, and an
owner-attested interval containing current time in the recordings' declared clock coordinates.
The program does not read or trust the host clock on the owner's behalf. For example, after
setting the two bounds from the owner's clock assessment:

```sh
fss-event delete retention-plan \
  --root /path/to/deployment --site site:home \
  --sensor-id sensor:front \
  --retain-for-ns 86400000000000 \
  --attested-now-ns "${EARLIEST_NOW_NS:?supply earliest current time}:${LATEST_NOW_NS:?supply latest current time}"
```

The example duration is one day. Both current-time endpoints are signed 128-bit integer
nanoseconds; a point interval is permitted. Capture time and current time are explicitly
**owner assertions, not independently observed or calibrated clock alignment**.

The preview returns `fss.retention_cleanup_preview.v1`, including each completed same-sensor
recording's disposition and immutable manifest/capsule-timing bindings. It separately reports
incomplete imports, which are never selected, and the count of other-sensor imports. Unknown
capture time, any source gap, substantive source omissions, uncertain age, and arithmetic
overflow retain the recording. Annex-B padding alone is not a substantive omission.

For each otherwise admissible recording, the selector computes the interval of its last
capture by taking the maximum lower bound and maximum upper bound of all capsule intervals.
Selection requires:

```text
latest_possible_last_capture + retain_for_ns <= earliest_attested_current_time
```

It never uses receive time, the first frame's time, a midpoint, or filesystem modification time
as a substitute. If even the latest current-time assertion precedes the earliest possible
deadline, the result is `not_due`; overlapping uncertainty gives `age_uncertain`.

## Plan toward a source-byte target

Add `--max-retained-source-bytes BYTES` to request a deterministic oldest-first sequence
of safely deletable, age-eligible recordings that stops once it meets the target:

```sh
fss-event delete retention-plan \
  --root /path/to/deployment --site site:home \
  --sensor-id sensor:front \
  --retain-for-ns 86400000000000 \
  --attested-now-ns "${EARLIEST_NOW_NS:?supply earliest current time}:${LATEST_NOW_NS:?supply latest current time}" \
  --max-retained-source-bytes 1073741824
```

Here the source-byte target is 1 GiB. The minimum age remains one day: storage pressure never
makes a recent, uncertain, gap-containing or held recording eligible. A zero-byte target is
valid but still cannot override those exclusions. Candidates are considered by latest possible
capture end, then immutable import identity. Every proposed union passes the existing deletion
and hold checks before it can join the selected cohort. Once the target is reached, other
age-eligible imports receive `budget_retained`; they are not selected for deletion.

The accounting is **distinct completed input files for the named sensor**, using the verified
manifest's input digest and byte length. If several imports reference the same input, that
input is counted once and leaves the projected total only when all its same-sensor imports
are selected. Recent, unknown-time, blocked and otherwise retained completed imports still
count. Incomplete imports are reported separately and are outside this bounded total.

This total is different from physical disk usage. Other sensors may share source objects;
derivatives, authority history, original input files, remote copies and filesystem overhead
also have their own lifetimes. The nested deletion plan lists the exact local objects and
bytes it can unlink. Neither this logical target nor an upload acknowledgement proves freed
disk capacity.

The selection's `source_byte_budget` reports `before_source_bytes`, `selected_source_bytes`,
`projected_remaining_source_bytes` and `unmet_source_bytes`, along with the exact limit and
accounting scope. `selected_source_bytes` counts distinct inputs with no retained same-sensor
member after the proposed cleanup. An unmet target remains explicit; independently safe
progress may still have an approval command. A blocked final deletion plan remains blocked,
even when its hypothetical selected cohort would meet the target. An already satisfied
target returns no deletion plan or approval. No byte-total field implies that a cleanup has
already executed.

Follow the exact `approve_command` from the preview. It includes the byte target. Omitting or
changing that target, even to a more permissive value, cannot reuse the approval; neither can
changing the source inventory, hold state, minimum age or time assertion. Interrupted commits
resume the sealed original cohort and never enlarge it to make up a newly observed deficit.

## Exact approval, one transaction, safe restart

When something is eligible, the nested `deletion_plan` contains the complete closure, objects
kept and removed, derivative tombstones, root retractions, blocked effects, holds, unknown
copies, plan digest, approval digest and exact `approve_command`. Inspect that plan before
running its command. A blocked preview has no approve command. A preview with no eligible
recordings returns `nothing_eligible` and `deletion_plan: null`. If expired recordings exist but every admissible closure is blocked, the preview returns `blocked` and explicit exclusions, with no deletion approval.

The command has this shape; use the exact values returned by the preview:

```sh
fss-event delete retention-commit \
  --root /path/to/deployment --site site:home \
  --sensor-id sensor:front \
  --retain-for-ns 86400000000000 \
  --attested-now-ns "${EARLIEST_NOW_NS}:${LATEST_NOW_NS}" \
  --plan "${PLAN_DIGEST}" --approve "${APPROVAL_DIGEST}"
```

Preparation uses `CAP-DELETE-PREPARE-001`; commit uses `CAP-DELETE-COMMIT-001`. An explicit
principal is supported and is bound into the approval. Fresh commit recomputes the same
selection and complete closure under the current authority/effect heads. A changed time
assertion, duration, sensor, later import, hold, or other head change does not inherit an old
approval. No caller-supplied object list or deletion plan can directly authorize unlinking.

The selected recordings form **one union closure**. Objects shared with retained recordings
are kept and listed. If the whole expired cohort is safe, planning keeps the original v1
selection bytes. If it is blocked, candidates are evaluated in import-identity order. A
candidate is added only if its union with the preceding accepted candidates remains safe.
Independent expired recordings can therefore be cleaned up while held or otherwise blocked
recordings remain retained.

A rejected candidate receives the `closure_blocked` disposition, its exact blocker findings,
and the digest of the attempted union plan. Holds on shared derivatives and source bytes
needed by open effects still block every union that would affect them. An individual import
being safe does not imply that a larger union is safe. The deterministic selection makes
bounded progress; it does not claim to find the largest possible removable cohort. Final
aggregate publication bounds remain enforceable even after candidate filtering.

Cleanup never expires or releases a hold, even when its requested age has elapsed. Releasing
or expiring a hold remains a separate owner action. A new or released hold, newly completed
import, changed head or changed time assertion requires fresh approval.

Once the deletion record is durable, retry uses its exact retained v3 plan instead of
recalculating a larger age cohort. It needs neither the original input files nor source bytes
already removed by the interrupted deletion. The same approval finishes removal and publishes
one completion record. A later exact retry returns `already_complete` without duplicating
history. A different request cannot borrow the old plan's successful completion.

Removal is only `filesystem_unlink` inside the deployment. It is not cryptographic erasure.
Original input files, exports, backups, replicas and device remanence remain explicitly outside
this proof. Event revision history is preserved, with deleted evidence availability kept
orthogonal to conclusions about the physical world.

## Bounds, formats and compatibility

The selector admits at most 256 nondeleted import identities (including incomplete imports),
16,384 capsule records and 64 MiB of manifest/capsule metadata per pass. Its own indexing and
capsule-binding scan has a one-million-entry ceiling. The retained reader and deletion closure
keep their existing limits; selector counters do not purport to measure all storage or closure
work. Planning uses one age assessment, one reusable dependency scan, and one cached projection
per distinct held closure. Candidate-union evaluations reuse those structures; they can still
read retained event metadata, so the closure-scan counters are not a measurement of every
physical I/O operation. The preview reports closure evaluations and held-closure counts.
Fresh commit independently recomputes the selection and final plan. An oversized inventory
is refused, never sampled or truncated. This is not yet a paged large-installation retention
scheduler. It reads no media pixels to decide age.

Version-1 import deletion and version-2 sensor/event deletion keep their canonical layouts.
The new `DeletionScope::Retention` uses scope tag 4 only inside `fss.deletion_plan.v3` and
`fss.deletion_completion.v3`. Unblocked requests retain the entire `fss.retention_selection.v1`
encoding. Requests with explicit closure exclusions use `fss.retention_selection.v2`, which
adds each exclusion's trial-plan digest and bounded canonical blocker list. A blocked entry
must be age-eligible and have both a witness and nonempty findings; v2 without any exclusion
is refused. Readers check that the plan's member list equals precisely the eligible entries.
Old readers reject an unknown inner domain. Existing v1 durable deletions retain their exact
retry semantics; there is no down-conversion or rewriting of retained approvals.

Requests with a source-byte target use `fss.retention_selection.v3` inside the same deletion
v3 envelopes. This inner format binds the optional request target, each candidate's source
digest and length, every selection/exclusion and closure witness, and the recomputable byte
accounting. The decoder rejects inconsistent source lengths, forged totals or eligibility,
and noncanonical ordering. Neither age-only v1 nor blocker-aware v2 bytes change. Old readers
refuse the unknown selection version instead of interpreting a byte-limited approval as an
unlimited age-based deletion.

## Focused regression checks

```sh
bash scripts/check_retention_reference.sh
```

The script runs selector/codec and CLI unit tests, `retention_cli_contract`,
`retention_cohort_contract`, and existing import/sensor/event deletion integration targets,
then formatting checks.
The new tests cover real retained MJPEG imports, old versus recent and unknown-time recordings,
shared source preservation, derived-frame deletion, holds, stale requests, version/member
forgery, explicit no-op results, all six deletion interruption points, and cold exact retry.
The optional hosted workflow invokes this same script and does not replace local DSR gates.

On 2026-11-09, a linked native UTC test build and a metadata-only check that included
`retention_cohort_contract` both exited 101 in unchanged Asupersync 0.5.0 with compiler
signal 9. They used the complete pinned nightly, locked offline dependencies, one Cargo job,
no incremental compilation and zero debug information. Neither reached the changed Rust
paths. The 16 new retention tests remain unexecuted. The schema suite passed 64 cases with
one existing skip; scoped formatting and changed-file integrity checks also passed. See
[the exact commands and shared scope](../IMPLEMENTATION_STATUS.md#retention-and-utc-catalog-set-validation--2026-11-09).

The source-byte contracts additionally exercise oldest-first stopping, complete-input
deduplication, shared inputs across sensors, holds and union-only effect blockers, unknown-time
accounting, unattainable targets, stale inventory and holds, exact-budget CLI approvals, and
every interruption cut with cold retry. Canonical decoder cases reject forged totals,
inconsistent source lengths, missing v3 fields, overflow and skipped older candidates.

Related contracts: FSS-037, GOAL-009, GOAL-010, CAP-DELETE-PREPARE-001 and
CAP-DELETE-COMMIT-001. Standing `EFFECT-RETENTION-001` policy adoption, encrypted storage,
automatic scheduling, live-capture archive selection, replica deletion and large-inventory
pagination are not implemented by this slice.

The cohort additions include nine real-import contracts for independent and shared holds,
union-only effect blockers, unchanged v1 selections, stale approval, cancellation, all deletion
cut points, cold retry and path independence. Their final compilation, execution and formatting
were interrupted by execution-environment loss on 2026-11-07; authored tests are not a pass.
