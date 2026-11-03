# Recover captured learning with a replacement session

An authorized replacement session can inspect an exact captured-learning publication from an
earlier session of the same principal and immutable mission. The original session may already
be cancelled or expired. Its retained journal, workspace and complete learning source closure
must still verify.

This is an explicit selection through the existing AOP-011 `explain` operation. Ordinary
orientation and handoff inventories remain scoped to their own session; selecting an old root
does not add it to the replacement session's inventory or workspace.

## CLI

Keep the learning publication root returned by the original `feedback` capture or its orientation.
Use that root with a currently admitted replacement session:

```sh
fss explain --json --root ./deployment \
  --principal principal:local-operator \
  --session session:REPLACEMENT \
  --learning-root sha256:ORIGINAL_LEARNING_PUBLICATION \
  --view forensic --budget-tokens 16000
```

The identifiers above are placeholders. Supply the actual returned session ID and full SHA-256
publication digest. The request needs no reconstruction of the old feedback statement, plan
arguments or source citations.

Open the replacement with exactly the original mission statement and objective, under the same
principal and deployment. A matching mission label with a different objective is refused. The
native mission publications and their workspace membership are verified before historical data
is disclosed.

An identical opening request at an unchanged deployment position recovers its original session
identity; it cannot reopen a cancelled session. Choose the response view and cumulative token
allowance appropriate for the replacement, or open at a newer deployment position. For example,
if the original opening used a 64,000-token allowance, a fresh opening for the same mission and
objective can use 63,000 tokens:

```sh
fss session open --json --root ./deployment \
  --principal principal:local-operator \
  --mission-text 'EXACT ORIGINAL MISSION STATEMENT' \
  --objective 'EXACT ORIGINAL OBJECTIVE' \
  --view epistemic_map --budget-tokens 63000
```

Use the new returned session ID in `explain`. A forensic answer can request up to its registered
view ceiling, subject to the remaining current session allowance. An undersized response budget
refuses the complete answer instead of omitting candidate details or uncertainty.

## MCP

Use the same existing `explain` tool with the server configured for the current owner and
deployment. Root paths and principal labels are not supplied through the tool arguments:

```json
{
  "name": "explain",
  "arguments": {
    "session": "session:REPLACEMENT",
    "learning_root": "sha256:ORIGINAL_LEARNING_PUBLICATION",
    "view": "forensic",
    "budget_tokens": 16000
  }
}
```

CLI and MCP call the same native reader and produce the same semantic answer for the same
admitted request. The current live session must retain explanation, session-read and
situation-read capabilities, private-property scope and sufficient budget. Possession of the
learning root or the old session's grants supplies no current authority.

## Read the two provenance positions

The response envelope's `sessionId` and `inputAnchor` identify the replacement and the currently
observed deployment. The `current:authority` proposition records its workspace, journal and
remaining token allowance; its `anchor` agrees with the envelope's current `inputAnchor`.
The learning payload's `basisAnchor` retains the original evidence anchor and agrees with the
`experience:basis` proposition, even when the current deployment has advanced.

The `capture:custody` proposition carries the unchanged learning, experience, proposal, episode,
feedback and plan digests, the captured workspace digest, and `capturedSessionId`. These fields
identify the original capture even when its source session is closed. Neither the source session
nor the candidate's review or expiry deadline is renewed.

Successful reads leave journals, ROOT pins, publications, workspaces, grants and budgets
unchanged. Exact retries recover the same original capture without recreating missing custody.
Missing or inconsistent selected records, tombstones, foreign ownership or a different mission
produce a refusal without private candidate details.

The candidate remains captured advisory history. Its statement, applicability and causal value
remain qualified by the retained uncertainty; inspection grants no promotion, policy activation,
source-media disclosure or effect authority. Review all retained validation requirements and
counterexamples before using the candidate in a future plan.
