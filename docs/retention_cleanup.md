# Owner-approved age-based recording cleanup

`fss-event delete retention-plan` selects an exact cohort of completed file imports for one
sensor. `retention-commit` executes one sealed union-closure deletion under its exact approval,
using the existing tombstone-first, local unlink, verification and completion protocol.

This implements one-shot age-based cleanup, not a standing retention policy, daemon, automatic
hold release, or remote archive deletion. The policy-change work packages remain open. It is a
reference implementation, **not production-qualified**. Native Rust execution and formatting
were not available when the initial implementation was committed; the focused checks are
executable but their presence is not proof that they passed.

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

## Exact approval, one transaction, safe restart

When something is eligible, the nested `deletion_plan` contains the complete closure, objects
kept and removed, derivative tombstones, root retractions, blocked effects, holds, unknown
copies, plan digest, approval digest and exact `approve_command`. Inspect that plan before
running its command. A blocked preview has no approve command. A preview with no eligible
recordings returns `nothing_eligible` and `deletion_plan: null`, not a deletion approval.

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

The selected recordings form **one union closure**, not a sequence of per-import deletions
whose later approvals would already be stale. Objects shared with retained recordings are
kept and listed. An active hold on any selected import, or on a shared derivative that the
plan would remove, blocks the whole cohort. Cleanup never expires or releases a hold, even
when its requested age has elapsed. Releasing or expiring an existing hold remains a separate
explicit owner action; changing a cleanup request is not a substitute.

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
work. Planning an eligible cohort performs two selection passes: assessment and independent
revalidation before the closure scan; the preview reports both. An oversized inventory is
refused, never sampled or truncated. This is not yet a paged large-installation retention
scheduler. It reads no media pixels to decide age.

Version-1 import deletion and version-2 sensor/event deletion keep their canonical layouts.
The new `DeletionScope::Retention` uses scope tag 4 only inside `fss.deletion_plan.v3` and
`fss.deletion_completion.v3`. The entire `fss.retention_selection.v1` is embedded, binding both
selected imports and exclusions. Readers check that the plan's import list equals precisely
the eligible selection entries. A v3 scope relabelled v2 is refused. Old software that does not
understand v3 must fail closed when opening its records; no down-conversion is provided.

## Focused regression checks

```sh
bash scripts/check_retention_reference.sh
```

The script runs selector/codec and CLI unit tests, the new `retention_cli_contract` integration
target, and existing import/sensor/event deletion integration targets, then formatting checks.
The new tests cover real retained MJPEG imports, old versus recent and unknown-time recordings,
shared source preservation, derived-frame deletion, holds, stale requests, version/member
forgery, explicit no-op results, all six deletion interruption points, and cold exact retry.
The optional hosted workflow invokes this same script and does not replace local DSR gates.

Related contracts: FSS-037, GOAL-009, GOAL-010, CAP-DELETE-PREPARE-001 and
CAP-DELETE-COMMIT-001. Standing `EFFECT-RETENTION-001` policy adoption, encrypted storage,
automatic scheduling, live-capture archive selection, replica deletion and large-inventory
pagination are not implemented by this slice.
