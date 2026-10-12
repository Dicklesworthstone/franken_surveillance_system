# Native alert control through MCP

The local stdio MCP adapter exposes the existing AOP-007 `plan`,
AOP-008 `commit`, and AOP-010 `cancel` control grammar. The existing
AOP-009 `wait` tool continues to inspect durable progress. Each call returns
the native `fss/1 AgentResponseEnvelope` unchanged, including its payload digest,
execution boundary, uncertainty, proof pointers, obligations and safe-retry guidance.

The implementation delegates to the same typed `EffectCommand` and native
effect owner as `fss plan`, `fss commit`, `fss cancel` and
`fss-event alert`. MCP introduces no effect journal, operation identity,
approval algorithm, network sender, background worker, automatic retry or document reader.

## Operator scope and authority

The launching operator fixes the deployment root and principal. Tool arguments cannot override
either. The principal is an audit label; local stdio process access remains the operator boundary.
These tools do not implement remote authentication or authorize another operator's devices or
recipients.

Publishing a plan is cognition. Preparation requires the exact native plan approval.
Dispatch separately requires the exact approval of the durable prepared operation, retained
route, deadline and principal. The relay is an exact literal IP:PORT, with a literal absolute
path and an owner-supplied plaintext approval. No DNS, vendor endpoint discovery, shell command,
SQL, generic HTTP request, free-form effect or path-loaded attestation is admitted.

The operator must inspect and authorize those concrete plans. An MCP description, returned
affordance, agent recommendation, request ID or discovered digest is not permission to act.

## Tool families

| Tool and intent | Required arguments | Optional arguments | Native behavior |
|---|---|---|---|
| `plan`, `intent: "alert"` | `session`, `event_id`, `relay`, `path`, `plaintext_approval`, `deadline_ms` | `case`, `approve` | Publish a witnessed ControlPlan; exact approval also prepares its alert. No dispatch. |
| `plan`, `intent: "close"` | `session`, `plan` | None | Record a terminal execution episode, or withdraw a never-prepared plan. |
| `commit`, `intent: "dispatch"` | `plan`, `approve` | None | Revalidate the retained prepared plan and make at most one native relay attempt. |
| `commit`, `intent: "reconcile"` | `operation_id`, `outcome`, `evidence`, `statement` | `approve` | Preview or record an exactly approved owner attestation. No network I/O. |
| `cancel` | `operation_id` | `approve` | Preview or exactly approve cancellation of a still-prepared operation. |
| Existing `wait` | `operation_id`, `deadline_ms` | None | Read the native durable receipt until its state changes or the bounded wait expires. |

Every family has its own strict key allowlist. Mixing dispatch and reconciliation fields,
supplying an approval to close a plan, unknown fields and root/principal overrides are refused
before native execution. All values go through the existing typed CLI parser. Inline options
keep text such as `@/owner/statement.txt --approve=...` literal; it is never opened
as a file and cannot inject another option.

Dispatch deadlines are integers from 1 through 60,000 milliseconds, retained in the plan and
bound into the dispatch approval. `commit` cannot replace the stored route or deadline.
The existing synchronous `wait` transport limit remains 10,000 milliseconds. An unchanged
operation at timeout returns a partial native answer with `ERR-OP-TIMEOUT-001`;
silence is not completion.

## Planning, preparation and dispatch

Call `plan` with the alert fields and no `approve`. The returned native
`fss.agent_control_plan.v1` identifies the plan, its event revision, witnesses,
conditional worlds, proposed steps and terminal obligations. The native publication retains the
exact canonical plan record and rendered DAG.

The plan response preserves the native proof-pointer sequence: publication root, rendered
control-plan digest, exact plan approval, event revision, session-journal root and anchor token.
A prepared response additionally includes the exact dispatch approval. Read the complete
execution boundary to distinguish a newly prepared operation from one already prepared or
dispatched; absence of a dispatch approval does not authorize deriving one.

After reviewing and authorizing the preparation, repeat the same alert plan with its exact
plan approval. This durably prepares the effect and returns its dispatch approval. It still
does not contact the relay. The prepared operation is shared with the ordinary CLI and
`fss-event alert` through the same event-revision/route identity.

Only after separate dispatch authorization call:

```json
{
  "name": "commit",
  "arguments": {
    "intent": "dispatch",
    "plan": "<retained native plan identity>",
    "approve": "<exact native dispatch approval>"
  }
}
```

The native owner checks its authority and witnesses before durably recording commitment and
performing the bounded relay attempt. Stale approvals, a changed event revision, unavailable
session authority, incompatible case witnesses and other native refusals retain their existing
error identities and recovery guidance. MCP does not silently rebase or substitute another plan.

Preparation first verifies that any published preview matches the complete plan record.
A changed case revision, route, deadline or rendering under that identity refuses before the
effect journal is prepared. The native planning guard retains exclusive session-journal
ownership through preparation and publication, and through the bounded dispatch and durable
receipt. Competing case mutations and session handoffs receive the native store-locked refusal
while that ownership is held.

A prepared plan cannot be newly committed after its case revision or session anchor changes.
Already committed operations remain report-only and are not resent after either change.
Plan identities retain their existing versioned definition: a different case at the same session
anchor cannot replace the old plan. Refresh onto current evidence through handoff/resume,
explicitly rebase a stale case, and compile a fresh plan at the new anchor; cancel an obsolete
prepared operation when appropriate.

A complete successful HTTP response means relay acceptance only. It never proves delivery to
a human, a read receipt, or that the alert was warranted.

## Lost replies and indeterminate effects

The native commitment is durable before network I/O. A lost acknowledgement, timeout or
untrusted relay response leaves the effect indeterminate. An operation past the prepared state
is inspected on a repeated commit and is never resent by this owner, including across a cold
MCP restart or a retry through the CLI.

A client can also lose the MCP response after the native effect advanced. Closed output,
disconnect and an exceeded transport response ceiling cannot roll back that effect.
Preserve the plan and operation identities, use `wait` to inspect retained state, and
follow the native reconciliation guidance. Do not create a new operation or recipient route
to evade deduplication. The commit tool intentionally does not advertise automatic idempotent
retry, despite the native protection against duplicate dispatch.

MCP notifications never execute tools. The synchronous stdio adapter cannot process an
in-flight cancellation notification while dispatch blocks. `cancel` is the durable
native cancellation operation, not cancellation of a JSON-RPC response.

## Cancellation, reconciliation and closure

Without approval, `cancel` returns the prepared receipt and exact cancellation approval
in the native proof pointers. Repeating with that approval records the cancellation. It can
never make a dispatched alert become “not sent,” and it never erases the effect journal.

For dispatched uncertainty, `commit` with `intent: "reconcile"` requires:

- The existing operation identity.
- `outcome: "delivered"` or `"not_delivered"`.
- The digest of the operator's independently obtained evidence.
- A literal statement of at most 1,024 UTF-8 bytes.

Without approval this previews the native attestation. Exact approval binds the attestation,
operation state, principal and deployment; recording it retains operator-asserted provenance.
It does not acquire evidence on the operator's behalf and never upgrades an attestation to a
provider receipt. Exact retries retain the native record; contradictory terminal attestations
are refused.

Once the native terminal conditions permit, `plan` with `intent: "close"`
records the immutable execution episode. The AOP-007 payload remains the native ControlPlan;
its proof pointers identify the episode rendering and canonical record. Open obligations and
indeterminate effects cannot be silently discarded. Residual uncertainty, including whether
a delivered alert was warranted, remains explicit after closure.

## Focused verification

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-mcp --test mcp_control_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test agent_effect_cli_contract
```

The process contracts build synthetic retained two-camera evidence and use only an owned
loopback relay. They cover native plan/CLI parity, exact approval separation, fixed principal
and scope refusals, notifications, durable cancellation, relay-ACK loss, owner-attested
reconciliation and immutable closure.

A separate contract closes the initialized MCP process's stdout pipe before submitting an
approved loopback dispatch. A fresh process then reads the durable operation and repeats the
request without another relay connection. This distinguishes MCP response loss from relay
acknowledgement loss.

These focused contracts contribute to TEST-AGENT-CONTROL-001 and transport equivalence.
They do not qualify authenticated remote transport, arbitrary effect families, real delivery
providers, full request-region cancellation or the controlled-host release matrix.
