# Bounded waiting from an exact follow anchor

`fss session follow --wait-ms` lets an operator or local agent wait briefly when
the current retained situation has certified no meaningful change. It returns
existing material or protected context immediately. The call is synchronous,
limited to 10,000 ms of new-work admission and at most 41 attempted deployment
history reads. An ordinary wait is read-only. An explicitly owned subscription
can combine waiting with its durable delivery and acknowledgement records.

```sh
fss session orient --json --root /path/to/deployment --view brief
fss session follow --json --root /path/to/deployment \
  --since 'anchor:THE-EXACT-TOKEN-FROM-ORIENT' --view brief --wait-ms 10000
```

Use the exact token returned by the first command. `--principal`, when supplied,
must remain the same. It is an operator audit label; the launching OS account and
explicit deployment root provide local read access. Waiting adds no remote
authentication, durable session authority, or permission to execute an effect.

Without `--wait-ms`, the existing immediate follow operation and its canonical
request bytes, payload and exact page continuations are unchanged. Waiting and
`--continuation` are mutually exclusive and are rejected together before I/O.
Drain the current immutable stream first. Then obtain or retain an exact
orientation anchor for a new bounded wait.

## Ordinary anchor waits

| Observation | Response |
| --- | --- |
| Initial material change, contradiction, persisting coverage gap, obligation, or other protected context | The ordinary complete-class-set follow page, immediately. No protected condition is hidden to keep waiting. |
| Initial harmless head advance with a native silence certificate | `partial`, `ERR-AGENT-RESNAPSHOT-001`, `resnapshotRequired: true`, null payload. |
| Any verified ledger or effect-journal anchor advance after a park | The same resnapshot response, with both exact anchor tokens in `proofPointers`. Reorient before continuing. |
| Deadline reached while the last completed read was certified quiet | `partial`, `ERR-OP-TIMEOUT-001`, null payload. The last actual comparison's proof pointers and cumulative known costs remain visible. |
| Explicit read-admission limit reached | `partial`, `ERR-BUDGET-EXHAUSTED-001`, null payload; no further read or park starts. |
| Caller-owned cancellation after an observation | `cancelled`, null payload, and the completed observation's known costs. |
| Source verification, exact-basis, context-budget, live authority or clock refusal | A typed refusal; earlier observations are never substituted for current verified truth. |

Before any complete comparison, an execution refusal uses the existing
`fss.cli_diagnostic.v1` shape. The implementation does not invent an evidence
timestamp to create an anchored envelope.

Only the native classifier's validated singleton `no_meaningful_change` with
its silence certificate permits a park. Every quiet repeat rereads verified
history and rehydrates retained sources. Deletion or tampering cannot be hidden
behind a cached certificate.

Before a quiet comparison parks, every exact source object supporting its selected
coverage witnesses is rehashed. Live/virtual source capsules must reproduce their
retained frame records. Recorded imports bind their completed authority, current
publication records, and all source payloads; typed independent parts are resolved
through their declared roots and the existing native publication plan. Opaque
payloads are never recursively interpreted as manifests. Committed deletions and
local tombstone/indeterminate state refuse reuse, even when the payload still exists.
These are bounded sequential observations, not an atomic filesystem snapshot.

The anchor compares the full authority binding and both committed journal
prefixes, including effect-journal presence and record count. An effect-only
advance therefore wakes the call even when the ledger commit sequence stays the
same. A harmless advance also wakes: this implementation does not enumerate every
intervening prefix and cannot prove that a protected transition appeared and
resolved between reads. The response requests a resnapshot instead of claiming a
complete subscription history.

## Wait on a durable acknowledged subscription

An owned subscription can use `--wait-ms` with the same original `--since`,
session, subscription label, view and page size used for its registration:

```sh
fss session follow --json --root /path/to/deployment \
  --since 'anchor:THE-ORIGINAL-SUBSCRIPTION-ANCHOR' \
  --session 'session:THE-OWNING-SESSION' --subscription overnight \
  --view brief --max-entries 64 --wait-ms 10000

# After processing the exact pending delivery, explicitly acknowledge its receipt.
fss session follow --json --root /path/to/deployment \
  --since 'anchor:THE-ORIGINAL-SUBSCRIPTION-ANCHOR' \
  --session 'session:THE-OWNING-SESSION' --subscription overnight \
  --view brief --max-entries 64 \
  --acknowledge 'sha256:THE-EXACT-RETURNED-DELIVERY-RECEIPT' --wait-ms 10000
```

The receipt is the `follow-delivery:` proof pointer (also carried after
`continuation:follow-ack:`). Keep the original registration anchor on every
retry. Do not substitute the latest result anchor or pass a separate
`--continuation`; the journal owns the contiguous cursor and any item pages.

| Durable observation | Response and retained state |
| --- | --- |
| A page is already pending | Return that exact native page and receipt immediately, including a quiet page created by an earlier immediate request. Reading it does not acknowledge it. |
| A real adjacent ledger or effect transition is available | Return its first exact page immediately. Even a harmless real transition is delivered; later transitions cannot replace it. The frozen replay horizon and remaining item pages keep their existing ACK semantics. |
| No page is pending, the acknowledged anchor equals the current head, and fresh native classification and source custody certify quiet | Release the agent-journal writer, then park. This private probe creates no pending delivery and performs no implicit ACK. |
| Deadline, cancellation or read/source budget exhaustion | Return a typed failure with null payload and cumulative known costs. An explicit ACK already committed remains visible as `follow-acknowledged:` and in the completed execution boundary. It is safe to repeat that exact ACK when the response's retry policy allows it. |
| Session closed, live authority lost, source custody failed, or pinned mission/workspace semantics changed during the park | Refuse further delivery. Earlier quiet is diagnostic history, never a current payload or proof of a continuously quiet interval. |
| Both authority and effect journals advanced without a retained total interleaving | Require an explicit resnapshot. Waiting adds no invented ordering between the two journals. |

Each poll reacquires the existing journal owner and rechecks the principal,
session grants, generations, immutable subscription settings and pinned semantic
history. A park holds no writer, so another process can inspect, close or update
the session. A subsequent semantic change invalidates the original replay scope;
it does not silently become historical mission context. Waiting neither renews
the session nor restores any spent session allowance. A cold retry recovers the
committed ACK and pending receipt through the same durable journal path.

The durable profile counts both initial history reads and under-lock
revalidations against the 41-read ceiling. Each initial read admits at most one
writer acquisition, so repeated registration lookup and semantic scans are also
bounded. The source read and envelope allowances below accumulate across all
polls in one invocation. Both orientations of every completed comparison,
including reconstruction of an explicitly acknowledged page, contribute to its
reported costs. Quiet source auditing also reports the extra exact-snapshot read.
Additional bounded journal and publication work is identified as incompletely
metered rather than assigned a fabricated zero cost.

The native entrypoint is
`fss_reference::deployment_session::follow::wait::follow_session_wait` with an
immutable `FollowSessionWaitBinding`. Its caller supplies both the existing
`FollowSessionControl` (including replay admission) and `FollowWaitControl`.
Callers can narrow history and source ceilings. The existing immediate command,
durable receipt domains, journal records and no-wait request bytes are unchanged.

## Clocks, work, and ownership

The deadline uses monotonic elapsed wall time supplied by the caller's control.
It is distinct from retained evidence time. Waiting neither extends a coverage
window nor refreshes a cursor, session lease, publication, or evidence timestamp.
No timed-out interval is certified as physical absence or uninterrupted quiet.

Checks are separated by caller-owned parks of up to 250 ms, shortened only toward
the existing deadline. A completed quiet probe and its required revalidations
are followed by at least that park interval before another poll; the final
shortened park reaches the deadline without admitting another read.
Native layout, journal, object, event and revision limits
remain in force. The read ceiling counts attempted reads, including a failing
read and a history-only check that observes an anchor advance.

Source custody has a separate **whole-invocation limit of 4096 read admissions
and 64 MiB of charged envelopes**, including exact publication metadata. An object
is additionally bounded by the invocation's native per-object limit. Each read
reserves its maximum envelope, including the spool header and bounded probe,
before I/O. Verified success releases only unused allowance; a failed read keeps
its full reservation. The net charged total never refills between comparisons.
Repeated references share one comparison's bounded cache; every later poll
rehashes the selected closure again. Source-budget exhaustion returns a null
payload and `ERR-BUDGET-EXHAUSTED-001`, with no further park.

Every completed comparison adds both native orientations' requested and consumed
vectors with checked arithmetic. Known source payload/publication bytes and source
read admissions add to those counters. Source accounting separately reports the
gross requested reservations and the net charged envelopes; the latter include
failed-read uncertainty and are not labelled exact consumed bytes.
`consumed.latencyMs` reports the last measured
monotonic elapsed time for the enclosing wait. Snapshot-stage CPU/latency, doctor
inspection, history-only verification, and failed reads' unreturned work are not
fully metered; the response says so and does not report them as zero-cost work.
The deadline gates new work, not an already admitted filesystem syscall: a
bounded read can finish after the deadline, and that overrun remains visible in
the observed elapsed time when available.

The ordinary read-only library entrypoint is
`fss_reference::agent_follow::wait::follow_deployment_wait`. Its immutable
`FollowWaitBinding` names the root, principal, original anchor, view, page size,
read limits, deadline, read ceiling and whole-call source ceilings. The explicit
wait request identity includes those fixed source ceilings too; no-wait request
bytes are unchanged. A caller-owned `FollowWaitControl` must
admit read, hydration, each source read (including cache hits), time and park boundaries under that exact binding and
live cancellation state. There is no default permissive control. Its synchronous
return drains the call; no worker, lock over sleep, or detached task remains.
Callers may reduce the native read ceiling, individual read bounds, and source
allowances with `FollowWaitBinding::with_source_limits`; they cannot enlarge them
or reduce the evidence scope to fit an exhausted allowance.

`fss_cli::follow_cmd::execute_follow_with_control` exposes the same renderer to
in-process callers with their own control. It requires an explicit wait option
and refuses its absence before I/O. The ordinary `execute_follow` entrypoint
keeps the immediate legacy behavior.

## Native MCP adapter

The owner-launched `fss-mcp` tool accepts the same optional `wait_ms` integer in
1..10000 on `session_follow`. Root and principal remain fixed by the launcher;
the tool cannot override them. It forwards the resulting FSS envelope without
reclassification, including `isError: true` for partial/refused exits.
`session`, `subscription` and an optional exact `acknowledge` may be combined
with `wait_ms`; they use the durable profile above. Notifications never
acknowledge a delivery, and transport restart does not consume the next page.

This is a bounded synchronous tool call. The native adapter does not service an
in-flight cancellation notification while it is executing that call; process
termination owns its shutdown. Native callers needing cooperative cancellation
supply a control. No network subscription, universal `AgentRequestEnvelope`
ingress, durable follow lease, or follow-latency SLO is claimed.

The focused contracts are `agent_follow::wait::tests`,
`deployment_session::follow::wait::tests`,
`crates/fss-cli/tests/follow_cli_contract.rs` and
`crates/fss-cli/tests/follow_subscription_cli_contract.rs`: virtual clocks over
real committed roots exercise deadlines, read caps, cancellation,
missing/tampered sources, cumulative custody limits, explicit ACK recovery,
writer release, live semantic/authority changes and adjacent ledger/effect
wakes. Real CLI and MCP processes preserve native pending receipts and typed
refusals across restart. These tests are reference behavior, not release
qualification of FSS-208, TEST-AGENT-FOLLOW-001, INV-107 or the follow SLO.
