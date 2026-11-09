# Owner-approved retention policies and recording cleanup

`fss-event delete retention-plan` selects an exact cohort of completed file imports for one
sensor. `retention-commit` executes one sealed union-closure deletion under its exact approval,
using the existing tombstone-first, local unlink, verification and completion protocol.

An optional source-byte target selects the oldest safe age-eligible imports first. The default
remains cleanup of every safely deletable expired import. Settings can be supplied explicitly
for one cleanup or inherited from one exact, durably adopted per-sensor policy revision.

Policy adoption and each cleanup have separate approvals. This implements durable settings
and exact one-shot deletion, without a daemon, standing authority over future evidence,
automatic hold release, or remote archive deletion. Continuous ring recording and automatic
enforcement remain open. It is a reference implementation, **not production-qualified**.
Native compilation and execution remain blocked by a
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

## Adopt and use durable per-sensor settings

`policy-plan` previews a complete prospective policy generation and the current inventory
affected by those settings. A policy stores an enabled/disabled state, positive minimum age,
optional logical source-byte target, exact sensor and bounded owner rationale. It preserves
the same exclusions, age floor and logical accounting described above. Every revision also
binds the current authority head, the prior revision, the owner-attested time used for its
impact assessment, and the affected selection and optional deletion-plan identities.

First adoption explicitly says `--expected-policy none`:

```sh
fss-event delete policy-plan \
  --root /path/to/deployment --site site:home \
  --sensor-id sensor:front --state enabled \
  --retain-for-ns 86400000000000 \
  --max-retained-source-bytes 1073741824 \
  --expected-policy none \
  --attested-now-ns "${EARLIEST_NOW_NS:?supply earliest current time}:${LATEST_NOW_NS:?supply latest current time}" \
  --reason 'Owner reviewed front-camera file retention'
```

The `fss.retention_policy_cli.v1` response includes the exact prospective record, generation,
approval digest, `approve_command`, and `settings_impact_if_enabled`. That impact lists the
selection, number of selected imports, quoted local deletable bytes and blockers; its
`deletion_authorized` flag is false. A disabled proposal still previews the supplied settings
as an explicit hypothetical impact. `policy-commit` with the exact returned command stages
the impact plan when one exists and the policy record, then commits one guarded authority
revision. **Adopting a policy does not delete any recording or approve its impact plan.**
The adoption itself changes the authority head, so cleanup requires a new preview.

Read current settings, including disabled generations, with:

```sh
fss-event delete policy-show \
  --root /path/to/deployment --site site:home --sensor-id sensor:front
```

Omit `--sensor-id` to list all current policies in sensor order. To update or disable a
policy, repeat the complete `policy-plan` request with the desired `--state` and settings,
and put its current `policy_digest` in `--expected-policy`. A stale predecessor is refused.
A new import, changed hold or authority head between preview and adoption changes the
approval; the original command cannot silently adopt against different evidence.
An exact retry of the current adopted request returns `already_current` without a write.
Policy history is immutable, and revision numbers increase rather than reusing old records.

To prepare cleanup from an enabled policy, use its exact digest and a fresh owner time
assertion:

```sh
fss-event delete retention-plan \
  --root /path/to/deployment --site site:home \
  --policy "${POLICY_DIGEST:?use the adopted policy digest}" \
  --attested-now-ns "${EARLIEST_NOW_NS}:${LATEST_NOW_NS}"
```

The sensor, minimum age and optional byte target are inherited. `--sensor-id`,
`--retain-for-ns` and `--max-retained-source-bytes` cannot be combined with `--policy`.
The preview's exact `retention-commit` command includes the policy pin, asserted time,
deletion-plan digest and deletion approval. Fresh planning and commit require that the
pin names the sensor's **current enabled** policy and that every inherited setting matches
the retained record. Policy approval is not deletion approval. Explicit inline cleanup
requests retain their existing separately approved semantics; the stored configuration is
not a new restriction on those owner requests.

Policy adoption/show use `CAP-RETENTION-PREPARE-001`; adoption additionally requires
`CAP-RETENTION-COMMIT-001`. Cleanup continues to use the existing deletion capabilities.
Missing or corrupt records, damaged retained impact plans, forged generations, shadowed
namespaces and broken predecessor chains fail closed. A generic ledger append cannot write
the policy authority family or its reserved object namespace.

The deployment lock serializes updates with cleanup. No new policy revision can be adopted
while a durable deletion is incomplete. Cancellation after staging the impact plan or policy
object leaves no effective revision: both are verified audit metadata, and reopening permits
the original adoption approval to be retried exactly. After the policy batch commits, a
post-commit cancellation does not report the completed adoption as a failure.

Once a cleanup's deletion record is durable, its original policy pin and exact request remain
resumable without the removed media. A completed cleanup can still return `already_complete`
after a later policy revision disables future use of its old pin. Such a retry cannot add
new imports, change the byte target or extend deletion authority to later evidence.

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

Policy-driven cleanup uses `fss.retention_selection.v4`, a single policy digest followed by
the unchanged inner v1, v2 or v3 encoding. Its decoder rejects nested v4 wrappers and unknown
inner domains before decoding their fields. The normal deletion-record byte bound remains
in force. Legacy selection bytes and their approvals do not change. Policy revisions use
`fss.retention_policy.v1`, `fss.retention_policy_id.v1` and
`fss.retention_policy_approval.v1` for record, stable object and approval identities.

Policy history is bounded to 256 sensors, 1,024 lifetime revisions, 8 KiB per record, and
64 MiB of aggregate record and retained-impact bytes per history pass. Each pass examines at
most one million ledger batch/delta entries and checks cancellation throughout. Adoption
checks that its new record and impact fit the future replay budget before staging anything.
Resolving a pinned request and validating its freshness are separate bounded history passes.
History is never evicted or truncated to make a new policy fit.

## Focused regression checks

```sh
bash scripts/check_retention_reference.sh
```

The script runs selector/codec and CLI unit tests, `retention_cli_contract`,
`retention_cohort_contract`, and existing import/sensor/event deletion integration targets,
then formatting checks.
The new tests cover real retained MJPEG imports, old versus recent and unknown-time recordings,
shared source preservation, derived-frame deletion, holds, stale requests, version/member
forgery, explicit no-op results, all seven deletion interruption points, and cold exact retry.
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
CAP-DELETE-COMMIT-001, plus CAP-RETENTION-PREPARE-001 and CAP-RETENTION-COMMIT-001 for
policy adoption. The VIT-006 continuous per-source/class ring, standing authorization for
future automatic deletion, encrypted storage, automatic scheduling, live-capture archive
selection, replica deletion and large-inventory pagination remain open.

The durable-policy extension adds 16 executable contracts: canonical policy/wrapper refusal,
unchanged inner formats, real-import adoption without deletion, current enabled pins, zero
budget with preserved holds/young/unknown sources, stale inventory/holds/authority, policy
staging cancellation, all seven cleanup cut points with cold retry, guarded authority and
damaged custody, CLI parsing and actual policy/cleanup command processes. These new cases
have not run: the metadata-only retry also received SIGKILL while compiling unchanged
Asupersync before it reached FSS code. Authored tests and source review are not a passing
native test result.

The cohort additions include nine real-import contracts for independent and shared holds,
union-only effect blockers, unchanged v1 selections, stale approval, cancellation, all deletion
cut points, cold retry and path independence. Their final compilation, execution and formatting
were interrupted by execution-environment loss on 2026-11-07; authored tests are not a pass.
