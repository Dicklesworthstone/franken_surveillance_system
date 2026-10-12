# MCP advisory feedback reference

The `feedback` tool projects the existing native AOP-013 command. It records an immutable,
evidence-linked proposal so a client can preserve a correction, adjudication, outcome signal or
learning candidate after investigating a case or reviewing a plan or operation.

The launcher fixes the deployment root and principal. A request names a live session; the native
owner authenticates it, checks the feedback capability and binds the proposal to that session's
exact evidence anchor. MCP invokes the public feedback-specific typed CLI parser and returns the complete native
response envelope, payload and decision fingerprint.

The generic OS argument tokenizer has a separate 4,096-byte token limit. MCP has its own bounded
UTF-8 frame and validates the feedback contract's full 16 KiB statement and 256-item evidence
bounds before constructing literal native `ArgToken` values. It then uses `parse_feedback_args`
directly, so the smaller OS transport limit does not silently narrow the native feedback contract.
Requests within both transports' limits produce the same complete native response.

## Request

```json
{
  "session": "session:returned-by-session-open",
  "target": "case:case:east-door",
  "kind": "policy_candidate",
  "statement": "Preserve the hallway counterexample before changing the policy.",
  "supporting": [
    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  ],
  "contradicting": [
    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  ],
  "disposition": "create_learning_proposal"
}
```

The sample identities and digests are placeholders. Use the session, target identities and evidence
handles returned by the native system.

| Field | Native meaning and bound |
| --- | --- |
| `session` | Required portable native session identity, at most 128 bytes. |
| `target` | Required `event:`, `case:`, `operation:` or `plan:` followed by the exact literal identity. Preserve prefixes already belonging to that identity: `case:case:east-door` refers to `case:east-door`. MCP bounds the whole target string to 16,384 UTF-8 bytes. |
| `kind` | One of the 12 existing native kinds listed below. |
| `statement` | Required literal text, 1..16,384 UTF-8 bytes. Paths, `@` prefixes and apparent command flags remain text. |
| `supporting`, `contradicting` | Optional arrays of SHA-256 handles. Together they must contain 1..256 supplied items. Every item is parsed; mixed types and malformed or comma-packed items are refused. |
| `disposition` | Optional native disposition; defaults to `record_only`. |

Kinds are `correction`, `adjudication`, `helpful`, `harmful`, `missing_evidence`,
`bad_affordance`, `bad_summary`, `adapter_quirk`, `runbook_candidate`,
`hard_negative_candidate`, `policy_candidate` and `model_candidate`.

Dispositions are `record_only`, `create_learning_proposal`, `open_case`, `requalify`,
`deprecate` and `operator_review`. Every disposition is recorded as a request. Recording feedback
does not perform the disposition or activate a policy, model, threshold, retention rule, privacy
change, identity decision or effect.

The native owner checks target grounding: an event at the session anchor, a case visible to the
session, an operation in the committed effect journal or a published plan. This projection adds no
target resolver, file reader or alternate evidence semantics.

## Evidence, provenance and retries

The adapter passes every supplied evidence item to the native parser. The native publication owner
then sorts and deduplicates each evidence side independently. A citation supplied on both sides
remains on both sides; distinct contradictory evidence is never filtered out.

The full `fss.agent_feedback_proposal.v1` payload retains the proposer, author session, exact basis
anchor, target, kind, literal statement, both evidence sets, requested disposition, privacy and
creation time. `activePolicyMutation` is always `false`.

The native proposal identity binds the author session, anchor, target, kind, statement, canonical
evidence sets and disposition. An identical retry from a fresh process returns the original
publication root and proposal fingerprint after rechecking authority, grounding and the complete
publication closure. Changed intent or another author session produces a distinct proposal.
An unavailable or corrupt manifest, canonical record or rendered child refuses recovery.

If evidence advances while the original session remains valid, an exact retry preserves the
original proposal and its anchor. The envelope explicitly reports that the deployment head moved;
head-bound request metadata can differ. This does not rebase the session or claim fresh support.

The response retains the native proof pointers, input anchor, capabilities, warnings, contradictions,
budget accounting, compression receipt and retry guidance. Its first proof pointer identifies the
root-last publication; the second is the domain-separated canonical proposal digest, also used as
the decision fingerprint. The retained rendered child is the native minimal projection, while the
MCP payload is the full registered CLI rendering.

JSON-RPC notifications do not execute feedback. Unexpected fields, launcher-scope overrides and
malformed arrays fail before native execution.

## Contract evidence and remaining scope

`crates/fss-cli/tests/mcp_feedback_contract.rs` uses fresh MCP and CLI processes over native retained
evidence and real mission cases. It checks complete same-head response equality, immutable
canonical and rendered custody, response-loss retries, evidence-head movement, distinct changed
intent, principal isolation, all three custody objects under missing/corrupt faults, and malformed
or notification non-mutation. Mapping unit tests cover every native target family, kind and
disposition, including the combined evidence bound and literal statements.

This is the existing bounded reference proposal path. It does not implement adjudication review,
automatic learning promotion, policy activation or a new effect owner, and does not by itself close
the broader FSS-231 qualification work.
