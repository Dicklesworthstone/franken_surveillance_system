# MCP work claims and immutable findings

The MCP `investigate` tool projects the existing work-claim and finding intent families of
**AOP-006** onto the durable native mission board. These are the same transitions accepted by
`fss investigate --transition …`; the adapter constructs `ClaimArgs` or `FindingArgs` directly.
The launcher fixes the deployment root and principal. Every request names a live session of that
principal. Native session, mission, privacy, capability and journal admission remain authoritative.

This is a bounded reference implementation slice of **FSS-226** and **FSS-227**, governed by
the comprehensive plan sections 20.12 and 20.15. Those requirements remain open until their full
qualification, fault and resource-economy contracts are satisfied.

## Work claims

A claim reserves one exact unit of cognitive work in a visible case: the whole case, one
hypothesis, one discriminator, or one probe handle. The native owner derives its work root and
claim identity from that exact pair. Another session cannot reserve the same work independently.
Claims convey no effect authority; progress and result digests record cognitive artifacts.

All requests include `session` and the following native `transition`. Fields in brackets are
optional. Unknown fields and fields belonging to another transition are refused before execution.

| Transition | Additional fields | Native result |
| --- | --- | --- |
| `claim` | `case`, `work`, [`lease_ms`], [`depends`] | Reserve the exact work; an identical live opening retry reads its current revision without resetting progress or renewing the lease. |
| `claim-inspect` | `claim` | Read the retained head; reading never expires or renews its lease. |
| `claim-list` | None | List visible mission claims, including terminal audit facts. |
| `claim-activate` | `claim`, `expected` | Begin or resume work after every dependency completed at the admitted basis. |
| `claim-progress` | `claim`, `expected`, `artifact` | Attach an immutable progress digest while active. |
| `claim-block` | `claim`, `expected`, `artifact` | Preserve progress and mark the work blocked. |
| `claim-complete` | `claim`, `expected`, `result` | Record a terminal cognitive result. |
| `claim-release` | `claim`, `expected` | Release coordination without settling any external obligation. |
| `claim-renew` | `claim`, `expected`, [`lease_ms`] | Strictly extend the lease and advance its fence. |
| `claim-expire` | `claim`, `expected` | Explicitly record a lapsed lease as expired. |
| `claim-transfer` | `claim`, `expected`, `recipient` | Transfer to another live session of the same principal, mission and exact original basis; preserve or shorten the remaining lease and advance the fence. The recipient must activate explicitly. |
| `claim-reclaim` | `claim`, `expected`, [`lease_ms`] | Reacquire released, expired or authoritatively orphaned work with a fresh fence. |

`work` uses the CLI spelling: `case`, `hypothesis:<id>`, `discriminator:<id>`, or `probe:<id>`.
The item after the first colon is preserved literally, so a case probe named
`probe:hallway-frames` is selected by `"work":"probe:probe:hallway-frames"`.

`lease_ms` is an unsigned decimal JSON integer in **1..300000**, defaulting to **60000**. Leases
use the deployment evidence clock and must fit within the session expiry. Wall-clock waiting
does not advance that clock. Numeric strings, fractions and exponent notation are refused.
`depends` is an array of at most **64 distinct claim identities**; omission means no dependencies.

Every mutation requires the exact `decisionFingerprint` returned for the current claim as
`expected`. The digest is a compare-and-swap precondition, not permission. A stale revision,
foreign holder, invalid basis, lapsed lease or pending dependency produces the native typed
refusal. If a mutation's acknowledgement is lost, inspect the head before deciding on another
transition. Repeating an old mutation never resets progress or erases the new fence.

Example acquisition, followed by activation using the returned identities:

```json
{
  "name": "investigate",
  "arguments": {
    "session": "session:observer",
    "transition": "claim",
    "case": "case:east-door",
    "work": "probe:probe:hallway-frames",
    "lease_ms": 60000,
    "depends": []
  }
}
```

Read the claim identity from the returned cognitive proposition and the revision from the outer
`decisionFingerprint`, then supply them as `claim` and `expected` with `claim-activate`.

## Immutable shared findings

A finding publishes an agent-authored, evidence-linked claim about a visible case, optionally one
of its hypotheses. The native publication binds the author session, principal, mission, current
verified case revision, session anchor, recorded knowledge state, supporting and contradicting
handles, follow-ups and explicit finding links. The canonical record and its
`fss.agent_finding.v1` rendering are immutable children of a root-last publication.

| Transition | Additional fields | Native result |
| --- | --- | --- |
| `finding` | `case`, `claim`, `state`, `supporting`, [`hypothesis`], [`contradicting`], [`follow_up`], [`disagrees_with`], [`supersedes`] | Publish the typed finding; its content determines its identity. |
| `finding-withdraw` | `finding`, `claim`, `supporting` | Publish an immutable withdrawal of the exact active finding. |
| `finding-list` | [`case`] | List the mission board, optionally one case, with each finding's current standing. |

`claim` is literal statement text of at most **8192 UTF-8 bytes**. `state` is one registered
knowledge state: `known`, `estimated`, `unknown`, `conflicted`, `stale`, `not_observable`,
`redacted`, `indeterminate`, or `not_applicable`. A finding's supporting or contradicting digest
handles link its claim to evidence; publication itself does not certify a physical occurrence.

`supporting` must contain **1..256 distinct SHA-256 digests**. `contradicting` admits at most
**256**. `follow_up` and `disagrees_with` each admit at most **64 distinct portable identities**.
Arrays preserve every element; comma-separated strings, mixed types, duplicate entries and
oversized arrays are refused. Optional fields are omitted rather than sent as `null`.

An explicit disagreement between two active findings makes both visible as `conflicted`, while
preserving each immutable recorded state. The board exposes the unresolved conflict and its
probe affordances. Supersession or withdrawal ends the affected disagreement; earlier records
remain readable as `stale` audit facts. Native admission permits one successor per finding and
refuses a competing second successor.

The existing native finding API binds the current verified case revision while holding its
session journal. It does not accept a caller-supplied case `expected` digest. The MCP adapter
preserves that contract; it never simulates an atomic precondition with a separate pre-read.
Supersession and withdrawal identify their target by its exact immutable finding ID.

If a publication response is lost, an identical publish, supersession or withdrawal request can
recover its verified prior result at the same session and case basis. The native owner verifies
the original immutable record and complete publication closure before accepting that retry.
Another author session, altered content, changed case revision or competing successor is a new
request and does not inherit the old publication's retry admission. Missing or corrupt custody
refuses recovery.

## Response, custody and recovery boundaries

Claim and finding answers retain the canonical `fss.agent_response_envelope.v1` carrying
`fss.agent_cognitive_envelope.v1`: exact mission/session/anchor and contract basis, decision
fingerprint, evidence and proof handles, recorded knowledge, conflicts, budgets, compression
receipt and admitted affordances. Native refusals stay typed semantic envelopes with their
recovery guidance; malformed MCP arguments are JSON-RPC `-32602` errors. No host file is opened
from a tool argument. A path-like finding statement remains statement text.

The native session journal and agent publication store own all writes. The authority ledger,
effect journal, evidence spool and deployment `LAYOUT` remain unchanged by these operations.
Claim completion does not execute a probe, complete a plan, settle an obligation or authorize an
effect. Handoffs preserve the active claims and findings using the existing native projections.
This slice retains the current durable-follow refusal when semantic case/claim/finding history
cannot be replayed completely; it does not claim ordered replay of those workspace transitions.

## Retained process contract

`crates/fss-cli/tests/mcp_coordination_contract.rs` starts a fresh MCP process for every request
and checks two sessions sharing a mission, exclusive claims, dependency gates, progress recovery
after a lost acknowledgement, renewal/transfer fences, explicit evidence-clock expiry and
reclaim, immutable findings, symmetric disagreement, supersession, withdrawal and terminal audit
visibility, including exact lost-response retries and stale competing successors. It verifies
native recovered claim revisions, content-verified finding publications,
registered envelope and payload schemas, CLI semantic payload/fingerprint parity, handoff items,
fixed-principal admission, strict malformed-input refusal and unchanged authority stores.

Run the focused native contracts through the repository's pinned test environment:

```sh
cargo test -p fss-cli --bin fss-mcp coordination::
cargo test -p fss-cli --test mcp_coordination_contract
```

These focused checks supplement the repository-owned qualification and retained proof gates.
