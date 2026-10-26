# Native MCP reference adapter

`fss-mcp` connects a local MCP client to existing deployment reads and durable agent
sessions, investigations, advisory feedback and approved native alert controls. It is an
owner-launched stdio process. Tool names come from the same crosswalk as the CLI, and each
call executes the canonical CLI library in-process.

## Run

```sh
cargo build --locked -p fss-cli --bin fss-mcp
./target/debug/fss-mcp --root /absolute/path/to/deployment --principal principal:local-operator
```

`--root` is required and must already exist. The root is resolved at startup;
tool arguments cannot override it or the launcher's principal. The principal is
the native CLI's audit label, not remote authentication. The launching OS account
provides local access. Session lifecycle calls, investigation revisions, work claims,
findings, feedback proposals and explicit durable follow subscriptions write under `agent/`.
Alert control calls use the existing native effect journal and require the exact
approvals described in [Native alert control through MCP](MCP_CONTROL_REFERENCE.md).

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
| `investigate` (AOP-006) | `fss investigate` | Required `session`; eleven case, twelve work-claim and three finding transitions; native revision, lease and publication-retry fences |
| `plan` (AOP-007) | `fss plan` | `intent: alert` publishes a witnessed plan and optionally prepares it under exact approval; `intent: close` records its terminal episode |
| `commit` (AOP-008) | `fss commit` | `intent: dispatch` requires the exact prepared approval; `intent: reconcile` previews or records an approved owner attestation |
| `cancel` (AOP-010) | `fss cancel` | Required `operation_id`; exact approval records cancellation while still prepared |
| `wait` (AOP-009) | `fss wait` | Required `operation_id` and `deadline_ms`: 1..10000; reads existing effect state |
| `explain` (AOP-011) | `fss explain` | Required `event_id` |
| `handoff` (AOP-012) | `fss handoff` | Required `session` ID; optional literal `note` |
| `feedback` (AOP-013) | `fss feedback` | Required `session`, literal native `target`, `kind`, `statement` and 1..256 supporting/contradicting evidence handles; optional advisory `disposition` |
| `doctor` (AOP-014) | `fss doctor --root` | No arguments |

All except doctor return the **unchanged serialized `AgentResponseEnvelope`** in
MCP text content. Doctor retains its `fss.doctor.v1` diagnostic report. A nonzero
native CLI exit sets MCP `isError: true` while preserving the native error,
partial results, proof handles, recovery guidance and uncertainty.

Unknown fields are refused before execution. Discovery annotations describe the
tools; enforcement comes from explicit argument allowlists, the canonical CLI
parser, pure native intent decoders and an exact typed command allowlist. The
implemented control family is the native bounded alert workflow: plan, prepare,
dispatch, inspect, cancel, reconcile and close. It preserves existing operation
identities, approval digests, receipts and uncertainty about delivery.

Work claims and immutable findings share the existing `investigate` operation.
See [MCP work claims and immutable findings](MCP_COORDINATION_REFERENCE.md) for
exclusive work acquisition, dependencies, progress, lease transfer/reclaim,
disagreement, supersession, withdrawal and verified recovery after a lost response.
These actions write the native mission board and grant no effect authority.

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

## Investigate with durable competing hypotheses

The `investigate` tool acts within an existing session. Every call requires its
`session` ID and a `transition`. Case changes return the unchanged native
`fss.investigation_state.v1` payload in an `AgentResponseEnvelope`; the
`decisionFingerprint` is the exact revision digest required by the next change.
The `list` transition returns the native cognitive-envelope summary.

Native case inspection records a command witness in the session journal. Repeated
inspections can therefore return the same case revision and decision fingerprint with
successive journal-root proofs. Use the fingerprint to compare case revisions and verify
each returned proof against its associated journal root.

| Transition | Additional arguments |
| --- | --- |
| `open` | `draft`: the literal case object |
| `inspect` | `case`; optional exact historical `revision` digest |
| `list` | None |
| `activate` | `case`, `expected` |
| `cite` | `case`, `expected`, `hypothesis`, `evidence`, `side`: support or contradiction |
| `assess` | `case`, `expected`, `hypothesis`, `evidence`, `disposition`: supported, disfavored or refuted |
| `set-state` | `case`, `expected`, `state`, `reason` digest |
| `conclude` | `case`, `expected`, `conclusion`: resolved or refuted, `stop_rule`, `assessment` digest, `residual_unknowns`: an array of IDs |
| `rebase` | `case`, `expected` |
| `readmit` | `case`, `expected`, `hypothesis`, `evidence`, `side`, `witness` |
| `expand` | `case`, `expected`, `expansion`: the literal expansion object |

`expected`, `revision`, `evidence`, `reason`, `assessment` and `witness` use native
`sha256:<64 hex>` digests. The state transition accepts `awaiting_evidence`,
`awaiting_approval`, `blocked`, `indeterminate`, `cancelled` or `closed`;
resolution/refutation uses `conclude` and the native stop-rule checks.
Use an empty `residual_unknowns` array only when no unknown remains. An ID
literally named `none` remains an ID, and duplicate residual IDs are refused.

For example, after opening a session:

~~~json
{
  "name": "investigate",
  "arguments": {
    "session": "session:returned-by-open",
    "transition": "open",
    "draft": {
      "caseId": "case:front-entrance",
      "question": "What explains the retained activity?",
      "decisionInformed": "Whether another observation is needed",
      "hypotheses": [
        {
          "hypothesisId": "h:person",
          "description": "A person crossed the entrance",
          "predictions": ["An independent view contains compatible motion"]
        },
        {
          "hypothesisId": "h:animal",
          "description": "An animal crossed the entrance"
        }
      ],
      "unknowns": [
        {
          "statementId": "u:identity",
          "text": "The source does not establish identity"
        }
      ],
      "discriminators": [
        {
          "discriminatorId": "d:side-view",
          "description": "Inspect retained independent-view evidence",
          "separates": ["h:person", "h:animal"],
          "expectedOutcomes": ["Human-compatible shape", "Animal-compatible shape"]
        }
      ],
      "probes": ["probe:side-view"],
      "stopRules": ["Retained evidence distinguishes the explanations"],
      "decisionWindowNs": "60000000000"
    }
  }
}
~~~

The `draft` uses the same native document grammar as CLI `--case-file`:
`caseId`, `question`, `decisionInformed`, `hypotheses`, optional `knowns`,
`unknowns`, `discriminators`, `probes`, `stopRules`, and exactly one of
`decisionDeadlineNs` or `decisionWindowNs`. The latter is relative to committed
evidence time. Decimal strings preserve full signed 128-bit nanosecond precision.
An `expansion` contains `hypothesis`, `discriminator` and `probe` in that same
grammar. These objects are decoded entirely from the bounded MCP frame.
Text that names a path remains literal data; file and stdin input are unavailable.

Native admission still checks the session's principal, mission, privacy domain,
lease, contract basis, case revision and evidence applicability. A case predating
a session rebase refuses changes until `rebase`; inherited citations need their
native applicability witness through `readmit`. Changing hypotheses or recording
a conclusion never executes a probe, dispatches an alert or verifies physical truth.

Cases and their immutable history survive MCP process shutdown. After an
interrupted call, inspect the case/revision and follow native retry guidance;
the tool does not promise unconditional idempotency. Handoff and resume retain
the native case references and expose stale applicability. An established case can
be included in a new durable-follow baseline at the current deployment head. A
later case mutation invalidates that subscription and requires explicit resnapshot;
it cannot be silently omitted from delivery or an acknowledgment.

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
resume does not implicitly acknowledge or migrate its pending delivery.

Established missions, cases, work claims, plans, findings, captured learning,
advisory context and supervision can now form a **pinned semantic baseline**. Open that subscription
using the exact current head from an explicit orientation and a new label. A
historical `since` is refused for a new populated baseline: current agent metadata
does not prove when it existed in earlier authority/effect history. Rebased
workspaces are supported under the same current-head rule.

Evidence-only advancement uses the unchanged pinned metadata and projects each
exact adjacent snapshot independently, preserving case applicability, claim expiry,
mission progress, plan freshness and effect uncertainty. Pending deliveries remain
identical across process restart and CLI/MCP retries even after the evidence clock
advances. Live authentication uses the current admitted clock; historical projection
does not move the session clock backwards.

Any retained semantic command or publication drift, including supervision changes
or a case created and closed between polls, requires `ERR-AGENT-RESNAPSHOT-001`
before consuming a pending acknowledgment. Re-orient explicitly, then use a fresh
subscription label and current head. The older pending delivery remains intact.
This profile does not synthesize a total history of agent-semantic mutations.
Existing empty-facet subscriptions keep their original sealed bytes and receipt
identity; no cursor or registration wire format changes.

Optional ordinary `wait_ms`: 1..10000 enables the
[bounded synchronous wait](AGENT_FOLLOW_WAIT.md) on a validated certified-quiet
head. Protected context returns immediately. An authority/effect anchor advance
requires resnapshot, including a harmless advance. A deadline does not extend
coverage or renew a lease, and an already admitted bounded read may finish after
that deadline.

## Evidence-linked advisory feedback

The `feedback` tool records a native immutable correction, adjudication or learning proposal
against an existing event, visible case, committed operation or published plan. It preserves
both evidence sides, author/session provenance and the exact session anchor. Requested
dispositions are recorded for review; submitting feedback does not activate a policy or effect.
See [MCP advisory feedback](MCP_FEEDBACK_REFERENCE.md) for the complete request, native
normalization, exact retry and publication-custody behavior.

## Wire behavior and limits

The negotiated version is **MCP 2025-06-18**. The server accepts `initialize`,
then `notifications/initialized`, `ping`, `tools/list` and
`tools/call`. The complete fourteen-tool list is returned in one response. Native
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
committed before this output check or before a broken pipe. An alert operation
may already have been committed or sent even if no MCP response arrived. Inspect
its retained operation with `wait`, then use native reconciliation and retry
guidance. Process shutdown does not implicitly acknowledge a follow page.

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
cargo test --locked -p fss-cli --test mcp_investigation_contract
cargo test --locked -p fss-cli --test mcp_coordination_contract
cargo test --locked -p fss-cli --test finding_cli_contract
cargo test --locked -p fss-cli --test mcp_control_contract
cargo test --locked -p fss-cli --test agent_effect_cli_contract
cargo test --locked -p fss-cli --test mcp_feedback_contract
```

Unit contracts cover exact dispatch, literal mission text, bounded cumulative
budgets, all twenty-six typed investigation, claim and finding transitions, literal nested intent data,
command and principal clamps, notification nonexecution, unchanged
semantic payloads, framing and output ceilings. Process contracts use real
reference deployments to check cross-surface identity, durable follow retries
and acknowledgments, session lifecycle, case history, world-drift invalidation,
claim lease and ownership fences, immutable finding retry receipts, exact native
plan/dispatch/cancel approvals, lost MCP and relay acknowledgments, retained
receipts without resend, native advisory feedback parity and publication custody, and authority
refusals. Native effect contracts also
hold a complete loopback request to prove that session and case mutation cannot
race an admitted dispatch. Included tests are not themselves test-pass or release qualification
receipts.

Protocol reference: `modelcontextprotocol/modelcontextprotocol`, specification
`2025-06-18`, `basic/lifecycle`, `basic/transports`, and `server/tools`.
