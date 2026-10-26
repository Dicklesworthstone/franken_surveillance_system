# MCP advisory feedback and experience reference

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
`deprecate` and `operator_review`. For an own-session `plan:` target with a retained terminal
execution episode, `create_learning_proposal` captures an immutable experience and learning
candidate. Its statement bound is 8,192 UTF-8 bytes. An explicit `open_case` disposition opens
an evidence-linked native investigation draft under the session's current case authority; it
retains the feedback statement's full native bound. The remaining dispositions record intent
without executing it. No disposition activates a policy, model, threshold, retention rule,
privacy change, identity decision or effect.

See [the episode experience reference](AGENT_EXPERIENCE_REFERENCE.md) for the complete capture,
proof-pointer and partial-failure contract. The ordinary feedback response described below remains
the result for requests outside that bounded capture profile. `open_case` keeps that feedback
payload and adds the native case result through registered proofs, execution boundaries and
investigation affordances.

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
root-last publication; the second is the domain-separated canonical proposal digest. Ordinary record-only feedback uses
that digest as its decision fingerprint. Case-producing feedback binds the original submission,
opening intent and current case revision instead; a new retry journal receipt alone does not
change its decision meaning. The retained rendered child is the native minimal projection, while the
MCP payload is the full registered CLI rendering.

JSON-RPC notifications do not execute feedback. Unexpected fields, launcher-scope overrides and
malformed arrays fail before native execution.

## Open a review case from feedback

Request `"disposition": "open_case"` with the normal feedback fields. The native owner retains
the exact feedback first, then opens one deterministic case named
`case:feedback:<feedback-publication-root-hex>`. Case creation requires the current investigation
and case-write grants plus the session's private scope. A plan target must additionally belong
to that exact session, mission and principal.

The draft contains three explicit Unknown alternatives: the statement is supported; it is
contradicted or misattributes the outcome; or the available evidence is insufficient. The known
fact is that the original submission exists in retained custody. Supporting and contradicting
citations remain review inputs until their source owners admit them; the draft does not turn a
label into a verified fact. Long literal statements stay complete in the original feedback
publication and response, rather than being copied into smaller case fields. MCP admits the
full 16 KiB native statement bound; the OS CLI keeps its separate 4096-byte token limit.

On success, the feedback envelope keeps its registered payload. After the feedback publication
and proposal digest, proof pointers identify the case, original opening digest, current case
revision digest and native session-journal receipt. The execution boundary reports the case
state and original decision deadline. The refreshed context provides ordinary registered
`investigate` affordances. Use that existing case lifecycle to inspect, activate, review and
conclude the draft.

An exact feedback retry recovers the same case's current revision, including work performed after
the first opening. It neither creates another case nor resets its state. The deadline remains
the original feedback evidence time plus one evidence-clock day. A native retry can append its
own command receipt while the case revision and decision fingerprint remain unchanged.

If case admission, journal pinning or subsequent response projection fails, the response preserves
the already-retained feedback and any known case revision. Its partial execution boundary
distinguishes completed state from possible append/pin progress. Preserve those identities and
inspect the native journal before treating ambiguous progress as absent; a new case identity
does not repair the original result.

Ordinary feedback still compiles the complete protected orientation before processing its
disposition. A full context can therefore prevent a retry; this case path does not provide an
unconditional inventory-independent recovery operation. Exact captured-learning reads use the
separate session-bound `explain` selector described in the
[native MCP reference](MCP_READ_ONLY_REFERENCE.md#read-one-captured-learning-proposal).

## Contract evidence and remaining scope

`crates/fss-cli/tests/mcp_feedback_contract.rs` uses fresh MCP and CLI processes over native retained
evidence and real mission cases. It checks complete same-head response equality, immutable
canonical and rendered custody, response-loss retries, evidence-head movement, distinct changed
intent, principal isolation, all three custody objects under missing/corrupt faults, and malformed
or notification non-mutation. Mapping unit tests cover every native target family, kind and
disposition, including the combined evidence bound and literal statements.

Captured experience is also discoverable through the existing session-bound `orient` tool. Its protected context carries exact learning identities, review/expiry status and residual uncertainty. `session.handoff` retains the complete verified capture graph. The first successful feedback response refreshes that inventory so an immediate exact retry has the same context; any downstream projection failure preserves the known publication roots in a typed partial response. See [the captured experience reference](AGENT_EXPERIENCE_REFERENCE.md#discover-captured-learning-and-carry-it-forward) for admission, custody and bounded replay behavior.

This is a bounded proposal, episode-capture and investigation-opening path. It does not implement
automatic truth adjudication, learning promotion, policy activation or a new effect owner, and
does not by itself close the broader FSS-230/231/232 qualification work.

Focused regression source in `agent_effect_cli_contract/feedback_case.rs` covers record-only
behavior, literal statement preservation, evolved-case retries, fixed deadlines, CLI/MCP recovery
and the retained-feedback boundary on a source-ownership refusal. Native case tests cover missing
authority and deadline admission. The selected-learning suite separately covers exact recovery
and current authority, including legacy sessions without an explain grant.
