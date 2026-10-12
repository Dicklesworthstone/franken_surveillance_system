# Native MCP reference adapter

`fss-mcp` connects a local MCP client to existing deployment reads and durable agent
sessions. It is an owner-launched stdio process. Tool names come from the same
crosswalk as the CLI, and each call executes the canonical CLI library in-process.

## Run

```sh
cargo build --locked -p fss-cli --bin fss-mcp
./target/debug/fss-mcp --root /absolute/path/to/deployment --principal principal:local-operator
```

`--root` is required and must already exist. The root is resolved at startup;
tool arguments cannot override it or the launcher's principal. The principal is
the native CLI's audit label, not remote authentication. The launching OS account
provides local access. Session lifecycle calls and explicit durable follow
subscriptions write under the deployment's `agent/` directory; they grant no
authority to mutate the evidence ledger, send an alert, or control a device.

Typical client configuration:

```json
{
  "mcpServers": {
    "fss": {
      "command": "/absolute/path/to/fss-mcp",
      "args": [
        "--root", "/absolute/path/to/deployment",
        "--principal", "principal:local-operator"
      ]
    }
  }
}
```

## Implemented tools

| Registered tool | Native operation | Arguments |
| --- | --- | --- |
| `session_open` (AOP-001) | `fss session open` | Required literal `mission` and `objective`; optional `view` and cumulative `budget_tokens` |
| `session_resume` (AOP-002) | `fss session resume` | Required published `handoff` ID |
| `session_orient` (AOP-003) | `fss session orient` | Optional `view`: `pulse`, `brief`, `epistemic_map`; optional response `budget_tokens`: 1..4096, subject to the view limit |
| `session_follow` (AOP-004) | `fss session follow` | Required `since`; optional `view`, `max_entries`, `continuation` or `wait_ms`; durable mode adds `session`, `subscription`, and optional exact `acknowledge` receipt |
| `query` (AOP-005) | `fss query` | Exact event, kind, state, zone and time filters; bounded pages with optional anchor and continuation |
| `wait` (AOP-009) | `fss wait` | Required `operation_id` and `deadline_ms`: 1..10000; reads existing effect state |
| `explain` (AOP-011) | `fss explain` | Required `event_id` |
| `handoff` (AOP-012) | `fss handoff` | Required `session` ID; optional literal `note` |
| `doctor` (AOP-014) | `fss doctor --root` | No arguments |

All except doctor return the **unchanged serialized `AgentResponseEnvelope`** in
MCP text content. Doctor retains its `fss.doctor.v1` diagnostic report. A nonzero
native CLI exit sets MCP `isError: true` while preserving the native error,
partial results, proof handles, recovery guidance and uncertainty.

Unknown fields are refused before execution. Discovery annotations describe the
tools; enforcement comes from explicit argument allowlists, the canonical CLI
parser and an exact typed command allowlist. Plan, commit, cancel, alert delivery,
repair, device controls and other effect tools remain unavailable.

## Open, hand off and resume a mission

After MCP initialization, open a session with literal mission and objective text:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "session_open",
    "arguments": {
      "mission": "Review retained activity around the front entrance.",
      "objective": "Preserve coverage gaps and investigate meaningful changes.",
      "view": "brief",
      "budget_tokens": 100000
    }
  }
}
```

The returned native envelope carries `sessionId`, `missionId`, the exact
anchor, workspace revision and publication proof handles. The mission is limited
to 8192 UTF-8 bytes and the objective to 4096 bytes; both must be nonempty.
`mission` is always literal, including when its contents name an existing file.
MCP maps it to the canonical `--mission-text` option, which performs no
mission-file inspection or read. The CLI's older `--mission` text-or-file option
remains available to direct CLI users. Those two CLI options are mutually exclusive.

The session's view defaults to `brief`. Its optional `budget_tokens` is a
**cumulative native session budget** in 1..1,000,000, separate from the response
budget of `session_orient`. If omitted, it defaults to the selected view's
registered maximum: 300 for pulse, 1600 for brief, or 3000 for epistemic_map. A
larger session budget does not widen per-response views or native evidence limits.

To retain a continuation graph, call `handoff` with the envelope's session ID
and, optionally, a nonempty note of at most 4096 UTF-8 bytes. The returned
`payload.handoffId` identifies the root-last publication. Start another
`fss-mcp` process for the same deployment and principal, initialize it, then
call `session_resume` with that handoff ID.

Resume uses native publication verification, recipient scope, evidence-clock
expiry, historical-anchor and workspace checks. It reports assumptions invalidated
by current world state before publishing any required workspace rebase. It does
not interpret stale context as current truth.

An identical open at the same full authority/effect-history head returns the
existing session and first workspace revision. An advanced full head can produce
a new session even if mission text is unchanged. Handoff identity also binds the
workspace and semantic state; resume can publish a rebase after world drift.
Lifecycle discovery therefore does not promise unconditional idempotency. Use
native session/handoff IDs, response receipts and recovery guidance after an
interrupted call.

## Follow delivery and acknowledgment

Ordinary follow performs one bounded read. Obtain `since` from an orientation
or session-open response. Keep it, the view and page size unchanged while using
the exact native continuation. Empty query matches and missing coverage never
certify physical absence.

For durable delivery, add both the opened `session` ID and a stable
`subscription` label. Native follow retains one pending page in the agent
journal. Repeating the request after disconnect returns that page until the
caller explicitly supplies its exact `acknowledge` digest. Each adjacent
history transition and every page must be acknowledged before progress advances.
The response's `continuation:follow-ack:` handle carries the acknowledgment
digest after its prefix.

Durable mode excludes manual continuations and bounded waits. It preserves a
frozen replay horizon and refuses a missing total order when both native journals
advanced. It also refuses changed authority, custody or pinned session semantics.
Handoff publication or workspace rebasing can invalidate an older subscription;
resume does not implicitly acknowledge or migrate its pending delivery. Honor the
native resnapshot response before establishing a new observation basis.

Optional ordinary `wait_ms`: 1..10000 enables the
[bounded synchronous wait](AGENT_FOLLOW_WAIT.md) on a validated certified-quiet
head. Protected context returns immediately. An authority/effect anchor advance
requires resnapshot, including a harmless advance. A deadline does not extend
coverage or renew a lease, and an already admitted bounded read may finish after
that deadline.

## Wire behavior and limits

The negotiated version is **MCP 2025-06-18**. The server accepts `initialize`,
then `notifications/initialized`, `ping`, `tools/list` and
`tools/call`. The complete nine-tool list is returned in one response. Native
durable follow state is accessed by explicit calls; there is no asynchronous MCP
subscription or task channel.

UTF-8 JSON-RPC objects are newline-delimited; batches are refused. Stdout contains
only protocol messages, and each response is flushed. Notifications never execute
a tool or mutate session state. Diagnostics go to stderr. EOF ends the process;
a partial final line is rejected.

Input is limited to 64 KiB including the newline, 32 nesting levels, 4096 values,
and 16 KiB per decoded string. Duplicate keys, malformed Unicode, invalid JSON
numbers and unrecognized fields are refused. Integer request IDs preserve their
exact spelling and must fit signed 64-bit range; string IDs are at most 128 bytes.

Semantic output is limited to 4 MiB before JSON escaping. Oversized output produces
an explicit error, never a truncated envelope. Agent state may already have been
committed before this output check or before a broken pipe; recover through native
retry/resume semantics. Process shutdown does not implicitly acknowledge a follow
page.

## Scope and qualification

This dependency-free synchronous adapter projects the implemented native CLI
operations. It does not implement full universal `AgentRequestEnvelope` ingress,
capability negotiation, arbitrary privacy projections, remote authentication,
in-flight cancellation, asynchronous live follow or FastMCP/Asupersync
orchestration. The registered session implementations retain their existing
reference limitations. No transport field silently changes those semantics.

The adapter does not qualify the surveillance pipeline or a release gate. Full
request-envelope admission and request-owned production transport remain open
under comprehensive-plan sections 20.6.1, 20.15 and 20.17.

## Contract checks

```sh
cargo test --locked -p fss-cli --bin fss-mcp
cargo test --locked -p fss-cli --test mcp_cli_contract
cargo test --locked -p fss-cli --test follow_subscription_cli_contract
cargo test --locked -p fss-cli --test mcp_session_lifecycle_contract
```

Unit contracts cover exact dispatch, literal mission text, bounded cumulative
budgets, command and principal clamps, notification nonexecution, unchanged
semantic payloads, framing and output ceilings. Process contracts use real
reference deployments to check cross-surface identity, durable follow retries
and acknowledgments, session lifecycle, world-drift invalidation and authority
refusals. Included tests are not themselves test-pass or release qualification
receipts.

Protocol reference: `modelcontextprotocol/modelcontextprotocol`, specification
`2025-06-18`, `basic/lifecycle`, `basic/transports`, and `server/tools`.
