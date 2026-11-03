# Revoke a retained agent session

`fss cancel --session` implements the session target of AOP-010. It revokes future use of one
owned session, clears its aliases, and retains an auditable closure tombstone. Existing plans,
work claims, workspace revisions, follow progress, pending deliveries, and external operation
records remain in custody. Session revocation does not establish a delivery outcome, settle an
external obligation, or complete a mission.

The command runs in an owner-authorized local process. `--principal` identifies that owner and
must match the retained session; it is an audit binding, not remote authentication. The process
supplies fresh `CAP-AGENT-CANCEL-001` authority. Stored session grants never authorize their own
cancellation, and opening a session does not automatically grant this capability.

## Preview and approve

Use the exact deployment and principal that own the session:

```sh
fss cancel --json --root /owner/deployment \
  --session session:... --principal principal:owner
```

The preview takes the existing session and deployment locks and verifies the bounded journal, its retained ROOT
pin, the session owner, and the complete admitted plan and obligation inventory. It does not
advance clocks, renew leases, consume session budget, append records, create a session store, or
repair the pin. Both locks use nonblocking acquisition. A busy session or deployment writer must finish before cancellation can proceed; a lock refusal
does not claim its work has drained.

The response is the registered `fss.agent_response_envelope.v1`, with AOP-010 and the existing
`fss.agent_cognitive_envelope.v1` payload. Review the authority proposition, retained-plan
propositions, and `payload.continuity.unresolvedObligations`. The exact SHA-256 approval appears
in `decisionFingerprint` and in the `session-cancellation-approval:sha256:...` proof pointer.

```sh
fss cancel --json --root /owner/deployment \
  --session session:... --principal principal:owner \
  --approve sha256:...
```

Approval binds the principal, session authority, complete session checkpoint and journal
predecessor, deployment authority and effect prefixes, evidence-clock time, and the retained
plan and unresolved-obligation inventories. A changed live preview is refused without silently
approving its new scope. Read and review another preview when the request has changed.

The approved transition appends one private journal command containing both the exact request
and the resulting tombstone. The same journal commit clears session aliases. It preserves
spent budget, workspace history and all coordination and external-operation records.

## Recover after interruption

Repeat the same command with the same approval after response loss. A cold process verifies
the original cancellation witness and returns its original receipt. The proof pointer
`session-cancellation-receipt:sha256:...` identifies that cancellation's journal record, even
when later records from other sessions have been appended. Repeated approved retries do not
append another tombstone, change its evidence time, or refill any allowance.

A ROOT-pin write can fail after the cancellation record commits. The response preserves the
known committed receipt and explicitly reports the pending pin repair. The exact approved
retry can advance a retained ancestor pin to the verified journal tip. It never accepts a
foreign pin, silently truncates an incomplete tail, recreates missing history, or converts an
expiry tombstone into proof of an approved cancellation. A torn journal requires the existing
explicit journal recovery procedure before the request can be retried.

A preview of an already cancelled session reports its retained original receipt without
repairing a lagging pin. Fresh cancellation capability and the same owner remain mandatory for
both inspection and approved retry.

## Continue work under a fresh session

The old identity stays closed. Repeating its original `session open`, using an old handoff to
resume it, or issuing another session-authorized command cannot resurrect that identity.
At an unchanged deployment head, a different admitted view or token budget creates a distinct
session for the same mission and objective; retain the new returned session identity.

Live work-claim leases are preserved by revocation. An admitted replacement session with the
same principal, mission, anchor and contract basis can explicitly reclaim a closed owner's
claim using the claim's exact current revision:

```sh
fss investigate --json --root /owner/deployment \
  --session session:new --principal principal:owner \
  --transition claim-reclaim --claim claim:... --expected sha256:... \
  --lease-ms 60000
```

The existing claim owner bumps the fencing incarnation and retains progress. The old session
cannot renew or mutate the claim. A changed anchor or grant still has to satisfy ordinary
claim-recovery admission; cancelling a session does not waive those checks.

Inspect prepared or dispatched external operations separately. `fss cancel --operation` is the
existing exact-approval path for a never-committed prepared alert. Dispatched or indeterminate
effects require their existing status and reconciliation operations. No external operation is
cancelled, resent, compensated or marked delivered by session revocation.

## MCP

The fixed-root, fixed-principal MCP `cancel` tool projects the same native owner and response:

```json
{"session":"session:..."}
```

After reviewing its preview:

```json
{"session":"session:...","approve":"sha256:..."}
```

Choose exactly one target, `session` or `operation_id`. Mixed targets, root or principal
overrides, unknown fields, and malformed approvals are refused by the transport's strict
grammar. The MCP process does not invent an approval or run an implicit retry.

## Bounds and evidence

The native owner replays at most the existing 64 MiB session-journal and 4,096-record limits.
Cancellation refuses an inventory larger than 256 retained plans or 256 unresolved obligations;
it never publishes a sampled prefix as complete. Native custody checks are bounded but not
fully metered in the public response budget fields, and that limitation is explicit in the
response. Inventories recovered on exact retry are historical facts at the original approval
position, so later operation outcomes must be inspected through their own current owner.

The implementation is covered by journal fault-cut and replay tests and by
`session_cancel_cli_contract`: read-only preview, current owner/grant admission, stale approval,
active-writer refusal, recovery across an append-before-pin crash, cold idempotent recovery, retained obligations,
old-handoff refusal, expiry distinction, MCP parity, and live-claim reclamation.
