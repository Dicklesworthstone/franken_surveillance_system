# Durable control retries and guarded retention

## Control request contract

The typed operational camera-supervision executor and MCP `plan`/`commit` route use
durable keyed daemon intake. This is an admission and retry contract. A queue receipt,
dispatch boundary, or subsystem return does not prove the physical or semantic outcome.

A preview returns both `approvalDigest` and `idempotencyKey`. Preserve both with the
original operation, target, deployment and principal. Commit requires the explicit key.
It does not regenerate a key from the current ledger anchor, because that could turn
a retry after unrelated writes into a second intended operation.

For example, these are MCP tool argument objects:

```json
{
  "intent": "camera-supervision",
  "op": "snapshot_camera",
  "camera_id": "sensor:front"
}
```

Pass the exact returned values to `commit`:

```json
{
  "intent": "camera-supervision",
  "op": "snapshot_camera",
  "camera_id": "sensor:front",
  "approval_digest": "<exact approvalDigest returned by plan>",
  "idempotency_key": "<exact idempotencyKey returned by plan>"
}
```

The placeholders above must be replaced with the returned nonzero SHA-256 digests.
The launcher supplies deployment-root, principal and capability authority. MCP arguments
cannot override those values.

The default preview key is deterministic over the deployment-root digest, principal,
complete input ledger anchor and approval under
`fss.ops_targets.camera_control_request.v1`. Repeating an identical preview at the
same anchor returns the same key. For a distinct intentional operation at an unchanged
anchor, supply a distinct explicit `idempotency_key` during preview and retain that
key through commit. A new key is not a way to recover a lost reply.

The daemon binds each key to exact operation, target, approval, principal and normalized
granted capabilities. Its verified journal header binds deployment, root and ContractBasis.
Connection and request IDs are correlations. Changing them does not create a new
operation; changing retained authority or intent under the same key refuses.

### Interpreting results

| Result | Meaning | Next action |
|---|---|---|
| `queued` or `accepted` | The daemon acknowledged this admission. | Observe the owning subsystem's evidence to establish the result. |
| `replayed`, `never_started` | The original admission exists; no dispatch boundary is retained at this observation. | Inspect progress. If recovered, it remains inert. |
| `replayed`, `dispatch_started` | A durable fence preceded possible subsystem execution. | Reconcile the original operation; its result can be unknown. |
| `replayed`, `subsystem_returned` | The subsystem returned to its caller. | Verify the subsystem's own postcondition and evidence. |
| `replayed`, `cancelled_before_execution` | The owner retained cancellation before subsystem execution. | A distinct future operation requires a distinct explicit intent and key. |
| `indeterminate` | Submission or its acknowledgement crossed an uncertain boundary. | Preserve the original key, approval and scope; repeat only that exact keyed request or inspect retained history. |

A successful replay returns the original `operationId`, retained `progress` and
`recovered` flag. It appends no admission, queues no command and grants no new execution
authority. Recovered entries are never automatically resumed, including entries that
were accepted but never dispatched. Retry inspection can resolve an existing key even
when fresh admission is blocked by queue capacity, shutdown or removal of its camera
from the current manifest.

A lost transport reply, mismatched response correlation, uncertain durable-history
refusal or post-submission cancellation is not reported as proof that no effect occurred.
The operational response retains its key, approval and original input anchor, uses
`outcome: indeterminate`, and records possible admission or dispatch. The registered
recovery class is `reconciliation_required`; same-request retry means the exact keyed
lookup/admission protocol, with no unkeyed fallback.

### Compatibility and custody

The IPC addition uses request tag 7 and replay-response tag 9. Existing unkeyed control
request tag 4 remains byte-compatible. Keyed journal admissions use tag 5; legacy
unkeyed admission tag 1 bytes remain unchanged and readable. Unsupported handlers and
process-local owners refuse keyed operations.

An older binary cannot decode new keyed history records. Treat rollback and journal
migration as explicit custody work; do not delete the journal, discard its pin, or
replace a key to make a refusal disappear. The history inspection schema adds an
optional nullable `idempotency_key`: null denotes a legacy unkeyed admission, and
omission remains valid for older producers. Consumers should use the matching updated
inspection schema.

These changes do not upgrade legacy unkeyed callers, authorize resumed execution,
provide physical device completion proof, or bind a mutable reload-manifest candidate
to its exact approved bytes. Those remain separate contracts.

The operational payload names `fss.agent_ops_intent_plan.v1` and
`fss.agent_ops_intent_commit.v1` predate this change. Their complete published payload
schemas and additive operation-profile registration remain open. The existing universal
envelope accepts these opaque payloads; consumers enforcing the operation registry's
narrower payload allowlist require that separate profile work. The new retry payloads
are not mislabeled as canonical ControlPlan or operation-receipt objects.

## Retention publication contract

The daemon obtains a `PreparedEviction` before canonical query retirement. Preparation
checks the exact deletion batch against current catalog references and tombstone reasons.
The per-store mutation fence then remains held while the daemon refreshes reference pins,
commits canonical retirement and commits the same prepared pack tombstones.

The daemon pin refresh includes retained import metadata: a foreign reference to that
metadata protects its source-media closure even though the metadata itself is retained
as permanent canonical history. A stale reference therefore refuses before changing
the canonical head or removing the footage row.

Catalog publication, supersession, root tombstoning, catalog compaction and interrupted
root cleanup acquire the same fence. Ordinary object appends and reads remain available
to the canonical combiner. Dropping preparation without committing changes no pack state.

This does not create an atomic transaction across the canonical ledger and pack catalog.
Interruption or I/O failure after canonical retirement can still leave partial durable
work. Exact-intent crash recovery across that boundary remains open. Existing hold
authority and format-specific graph closure checks still apply.

## Qualification and development handoff — 2026-11-27

The implementation addresses concrete gaps in `fss-x4a.30.1.7` / INV-007 and
`fss-vit-je36t.6` / `fss-x4a.13`. It does not close those broad requirements.

Independent source reviews checked locking, API compatibility, exact retry binding,
inert recovery, uncertainty projection and response correlation. New regression functions
and updated existing fixtures cover those boundaries. Embedded MCP tool schemas were
parsed and their camera-supervision branches checked, and changed-path content hashes
were verified.

Native Rust formatting, compilation and execution remain unverified. The first focused
build exhausted disk in unchanged `pkcs8` before tests ran. The execution host then
became unavailable; a brief return could not load the pinned Rust compiler shared
library before another disconnect. No retained passing qualification receipt exists
for these new bytes.

On a healthy pinned-toolchain host, the focused continuation is:

```sh
cargo +nightly-2026-08-31 test --locked -p fss-ipc --test ipc_wire_protocol --test ipc_contract
cargo +nightly-2026-08-31 test --locked -p fss-pack --test retention_reference_contract
cargo +nightly-2026-08-31 test --locked -p fss-daemon --lib control::journal::tests
cargo +nightly-2026-08-31 test --locked -p fss-daemon --lib storage::retention::tests
cargo +nightly-2026-08-31 test --locked -p fss-cli --lib query_cmd::ops_targets
cargo +nightly-2026-08-31 test --locked -p fss-cli --bin fss-mcp
cargo +nightly-2026-08-31 test --locked -p fss-cli --test operational_mcp_targets_contract
```

Run the repository's pinned formatting and relevant qualification lanes before making a
release claim. The highest-impact next implementation work is exact durable retention
intent recovery, immutable reload-candidate binding, and evidence-backed control outcome
reconciliation with an explicit operator resumption policy.
