# Current-format deployment backup and historical agent recovery

`fss-backup` makes a verified directory bundle of an existing deployment and restores
its exact historical snapshot to a new local root. The library owner is
`fss_reference::deployment_backup`; the planned work is FSS-035 (`fss-x4a.9.5`).
The original `reference-core-local-v1` profile remains byte compatible. A populated native
agent store selects `reference-local-with-agent-v1`, preserving sessions, workspace history,
cases, claims, missions, handoffs, plans, episodes, findings and feedback. Restored agent
state remains historical and read-only; copied grants and leases are never activated.

## Operator workflow

Quiesce the source first. Backup takes the existing deployment, spool and journal locks,
including the separate native session and agent-publication writers when populated,
without opening the source for mutation or reconciling effects. A held writer or unresolved
source recovery state produces a refusal.

```sh
fss-backup plan --root /srv/fss/site-a --allow-originals
```

Retain the reported `manifest_digest` independently. Replace `HEX` below with the 64
hexadecimal digits of that reviewed SHA-256; a digest obtained only from an untrusted copy
does not independently identify the expected snapshot.

```sh
fss-backup create --root /srv/fss/site-a --bundle /backups/site-a-001 \
  --expect sha256:HEX --allow-originals

fss-backup inspect --bundle /backups/site-a-001 \
  --expect sha256:HEX --allow-originals

fss-backup restore --bundle /backups/site-a-001 --root /srv/fss/site-a-restored \
  --expect sha256:HEX --allow-originals
```

Both output paths must be new, with existing regular parents. Existing destinations are
refused, including exact retries. Inspect retained work and choose a fresh destination
after any explicit cleanup. Source and destination trees cannot overlap. Plan, create,
inspect and restore emit bounded metadata-only JSON reports; `--json` is accepted but is
already the default. Reports contain the source anchor, core journal roots, capacities,
file and byte counts, and exact agent state metadata when present. They contain no original
media or complete file inventory.

Creation and restoration currently support Linux on x86_64 and aarch64. Their writers
hold the admitted destination directories open for the full transfer and activation.
Replacing a destination path cannot redirect original evidence into another directory;
the operation refuses when the admitted directory identity changes.

`--allow-originals` explicitly grants this local invocation original reads and the selected
copy destination. The library separately requires a `BackupAuthority` whose live checks
distinguish deployment reads, pinned bundle reads, exact bundle creation and exact restore.
These checks repeat during bounded I/O. A `ReplayCx`, content hash or path alone grants
none of those accesses. The CLI constructs its context at the existing working directory
so malformed or missing source paths cannot accidentally initialize a deployment.

Bundles contain unredacted originals and private cognition, stored in private new files
and directories. These profiles supply no encryption, remote transfer, key-store backup
or redaction.

## Committed scope and verification

The canonical `fss.deployment_backup_manifest.v1` encoding commits version 1, the exact
profile and source site, all nine original `DeploymentLimits`, the full source authority
anchor, both journal roots and lengths, total bytes, and a sorted inventory of whitelisted
relative paths, raw lengths and SHA-256 digests. The CLI JSON is a convenience projection,
not this commitment. Unknown versions and profiles are refused without migration.

The inventory contains `LAYOUT`, both complete journals, every admitted spool object
envelope, empty verification markers, publication roots and tombstones. Valid unreferenced
objects are retained because ledger-owned hold and deletion records can be outside the
current root graph. Existing native owners validate journal replay, object payloads, root
linkage, hold history and deletion records. Inventories are compared again after validation.

Incomplete deletion transactions refuse. Bytes denied by a committed deletion plan or
local publication tombstone must already be absent; backup cannot create another copy
of them. Partial journals, unresolved staging, corruption, foreign entries, unsafe links
and mismatched exact capacity policies also refuse without repairing the source.

A populated native `agent/` selects the additive canonical
`fss.deployment_backup_manifest.v2` encoding. It keeps the core commitment fields and adds
`AgentBackupSummary` before the complete inventory. The summary binds:

| Field | Preserved identity or count |
|---|---|
| `journal_root`, `journal_bytes`, `journal_records` | Exact committed agent journal prefix |
| `session_checkpoint` | All session state, aliases, disclosure charges and replay protection |
| `workspace_checkpoint` | Exact immutable workspace store, including every retained revision |
| `session_count`, `closed_session_count` | Retained sessions and closure/expiry tombstones |
| `workspace_revision_count`, `claim_count`, `case_count` | All workspace revisions and historical claim/case heads |
| `publication_count`, `publication_digest` | Ordered native publication slots, roots and metadata identities |

The inventory copies `agent/sessions/journal.fssj`, its exact `ROOT` pin, and every admitted
file of `agent/publications/`, including unreferenced originals and tombstones. Native
replay re-executes session, disclosure, workspace, claim and case verifiers. Publication
closure and each known native metadata format are verified through their existing owners.
Plan metadata must retain its exact control-plan child. A stale root pin, torn append,
unknown record kind, missing native directory or unfinished staging causes refusal; backup
never advances a source pin or initializes missing state.

All independent native agent locks are held throughout source inspection/copy, including
the session journal itself. Agent presence is checked against the acquired lock set, so a
newly populated directory cannot enter an unlocked snapshot. Lock files are excluded from
the bundle and recreated empty at restore; the native session journal and cryptographic
pin are copied exactly. Empty unused `agent/` remains compatible with the core profile.
External archives, caches, secrets and unknown subtrees require a separately specified profile.

`BUNDLE/MANIFEST` is published last after the copied payload has been reverified. A fixed,
required `RESTORE_INCOMPLETE` marker keeps `BUNDLE/payload` permanently inert. Removing
that marker invalidates bundle inspection. Ordinary deployment opening and explicit
journal repair both refuse the payload before changing its journals.

## Capacities and bounded work

Plan, create and agent-inspect use standard deployment limits unless overridden. Pass every changed
value if the source uses a custom policy; the supplied values must reproduce its original
`LAYOUT` limits digest. Inspect and restore use the full retained policy and refuse overrides.

| Source capacity | Source command option | Standard value |
|---|---|---:|
| Object payload bytes | `--spool-object-max-bytes` | 67,108,864 |
| Total spool payload bytes | `--spool-total-max-bytes` | 536,870,912 |
| Manifest children | `--manifest-children-max` | 16,384 |
| Authority batch entries | `--batch-entries-max` | 16,384 |
| Journal record bytes | `--journal-record-max-bytes` | 16,777,216 |
| Publication roots | `--max-roots` | 128 |
| Tombstones | `--max-tombstones` | 128 |
| Spool objects | `--spool-max-objects` | 65,536 |
| Directory scan entries | `--scan-max-objects` | 131,072 |

Each command also admits independent backup ceilings:

| Backup ceiling | Option | Default | Hard maximum |
|---|---|---:|---:|
| Inventory files | `--max-files` | 131,584 | 262,144 |
| File bytes, including spool header | `--max-file-bytes` | 67,108,916 | 268,435,508 |
| Total inventory bytes | `--max-total-bytes` | 1 GiB | 4 GiB |
| Canonical manifest bytes | `--max-manifest-bytes` | 32 MiB | 64 MiB |
| Bytes in each complete journal | `--max-journal-bytes` | 64 MiB | 256 MiB |

Each library operation shares one semantic-read allowance across inventory, read-only
snapshot validation, copy checks and revalidation: at most `128 × max_files + 10,000` calls and
`16 × max_total_bytes + 4 × max_manifest_bytes` bytes. Chunk loops recheck authority and
cancellation, with a fixed interrupted-syscall retry ceiling. Synchronous host syscalls
cannot be preempted. CLI create and restore first perform a separately bounded read-only
report preflight, then run the respective transfer against the same independent pin;
their execution context declares both metered allowances. Reports must fit 16 KiB before publication.
Agent histories additionally retain their native ceilings: at most 64 MiB and 4,096 journal
records, with the existing session, workspace, claim, case and agent-publication limits.
Increasing a backup read ceiling does not widen a native state-machine limit.

Restore's separate native fence-publication phase opens and stages through the existing
storage owners under the retained deployment capacities and admitted journal ceiling.
Those owner reads do not consume the semantic-read meter above, so the formulas are not
an aggregate bound on every host read performed during restoration. Authority and
cancellation are rechecked before and after these bounded owner operations.

Restore also needs capacity for the retained manifest, fence and new authority batch.
If those cannot fit the original deployment policy, it refuses instead of enlarging it.

## Restoration and external effects

Restore verifies the complete bundle before reserving a destination. It writes and syncs
an incomplete marker before copying historical bytes into new regular files. Failure
before marker creation can leave an empty reserved directory, with no copied authority;
a later interruption leaves a marked, inactive tree.

After copying and revalidating the bundle, restore preserves the source authority journal's
exact prefix and effect journal bytes, retains the manifest and restore provenance, and
appends `object:deployment:restore-fence` in reserved family `deployment_restore_fence`.
It holds the destination storage owners through activation. `LAYOUT` is written last,
the incomplete marker is removed, and directory durability is drained. A failure after
activation may be visible produces **indeterminate**, requiring inspection before retry.

Fresh files have fresh physical store identities; source pins are never forged. Historical
site, ledger epoch, event roots and source anchors remain historical. The new fence advances
the destination head. This is not a schema migration or a fabricated ledger universe.

A snapshot containing a `Prepared` alert cannot prove the original stayed unsent:

1. The original prepares the alert and backup captures that state.
2. The original sends the alert after capture.
3. The copied journal still says `Prepared`.

All supported alert preparation and dispatch paths therefore refuse restored deployments:
saved and rehydrated plans, in-memory and durable provider dispatch, and webhook commitment,
connection and writes. Cooperative cancellation drains its context without falsely changing
the copied operation to `Cancelled`; explicit owner cancellation also refuses. Pending
obligations remain pending. Generic appends cannot counterfeit, shadow or remove the fence,
and later unrelated evidence does not weaken it.

There is no unfence or automatic failover operation in either profile. Retained evidence can
be inspected and replayed; activating external effects needs a future explicit recovery
contract that can resolve source-side effects. Ordinary reopening may apply its existing
`Committed` to `Indeterminate` restart rule. Backup itself performs no effect reconciliation.

## Inspecting recovered agent history

Use the dedicated read-only command against an original deployment or a restored copy:

```sh
fss-backup agent-inspect --root /srv/fss/site-a-restored --allow-originals
```

It reports the canonical restore fence, exact checkpoint identities, historical sessions,
every immutable workspace revision, claim/case heads and all admitted native publications.
The session output retains spent-token and clock watermarks and closure tombstones. Cases
retain questions, alternative hypotheses, knowledge states, counterevidence and stop rules.
Claims retain recorded owners, revision digests, fencing incarnations, expiry, progress and
results, explicitly with `lease_admitted: false`. Handoffs retain unknowns, invalidations,
pending obligations and unresolved effects. Plans remain historical records.

Inspection does not open a mutable session store, advance a clock, expire or renew a claim,
resume a handoff, or update a workspace. It requires explicit original-custody permission
because these records include private operator text. All returned content is historical,
including when the source itself has not been restored. A report exceeding 16 KiB refuses
without truncation or omission.

For larger histories, the bounded library `inspect_agent_state` API takes the same source,
limits, `BackupAuthority` and `ReplayCx` arguments as `prepare_backup` and returns the complete
`AgentRecoveryState`. Its `SessionRecoveryState` includes exact canonical checkpoint bytes,
every retained session and workspace revision, and claim/case heads. Publications contain
typed `AgentRecoveryRecord` values plus exact slot/root/metadata/child identities. Claim and
case predecessor records remain in the byte-identical journal.

The canonical restore fence is custody-verified and parsed before both deployment-facing
agent writers: the session journal opener and the common publication owner. For a
with-agent restore, session open/resume, workspace or case commands, claim mutation and
new plan/handoff/finding/feedback/episode publication refuse without modifying history.
Existing pure plan and episode readers continue to inspect published history. Core-only
v1 restores contain no copied agent state and retain their existing ability to create fresh
sessions; their permanent alert fence remains active. Unknown or damaged fence policies
refuse agent writes, and no copied approval becomes effect authority.

Writer admission refuses symlinked directory ancestors and shared hardlinked session
journals or pins, so an unfenced deployment cannot write a restored agent subtree through
an alias. The guard runs before mutable opens, after writer-lock acquisition and before
session pin updates. These checks retain the existing trusted, exclusively owned directory
boundary; they do not introduce a general hostile-filesystem provider. The generic
low-level session store still requires a trusted, exclusively owned path and independently
admitted root. This feature adds no unfence, lease recovery or new trust-admission path.

## Errors and qualification boundary

The owning errors distinguish authority refusal, cancellation, locks, exhausted bounds,
unsupported state, corrupt custody, required source recovery, changed pins, existing
destinations, unsafe paths, I/O failure and uncertain activation. CLI errors use registered
`ERR-BACKUP-*` identities; effect gating reports `ERR-RESTORE-EFFECT-FENCED-001` through
existing owner wrappers. A refusal never authorizes overwriting, re-pinning damaged bytes,
resending copied work or silently repairing the source.

Focused regression targets cover the original core profile and the additive native agent
profile:

```sh
cargo test --locked --offline -p fss-reference --test deployment_backup_contract
cargo test --locked --offline -p fss-cli --test deployment_backup_cli
cargo test --locked --offline -p fss-reference deployment_session::
cargo test --locked --offline -p fss-reference alert_recovery_tests::
```

The populated-agent tests use native journal and publication owners, perform a cold restore,
compare complete checkpoint/workspace/claim/case/publication state, retain closed identities
and unknown alternatives, and verify that restored reads and refused writers leave all
bytes unchanged. They also exercise independent agent writer locks, stale pins, incomplete
journals, correctly framed but semantically foreign records, transient staging, unknown
subtrees and tampered payloads. Real-process tests exercise plan/create/inspect/restore and
the historical agent inspector under explicit custody permission.

The existing core cases exercise retained media/events, custom limits, holds, completed and
incomplete deletions, unreferenced objects, exact history, fresh physical pins, live
revocation, cancellation, invalid hold history, CLI refusals and effect fencing. Alert
fixtures send on the original after the snapshot and verify that restored preparation
cannot dispatch or falsely cancel. Destination substitution tests check that no original
bytes reach a replaced destination directory.

These reference/process checks do not qualify power-loss durability, storage devices,
schema migration, new active agent recovery, encryption/offsite backup, high availability
or the broad FSS-035 release contract. Supplementary hosted Rust tests are regression
evidence; the repository's canonical local qualification remains release authority.
