# Explain an exact retained event revision change

The existing `fss explain` operation supports `--question what_changed` for one
exact adjacent event revision transition. It compares complete committed event
metadata under the current deployment authority and returns the result through
the same protected AOP-011 cognitive response used by CLI and MCP explanations.

This answers what the retained declaration changed. It does not establish a
physical cause, restore an older permission, adjudicate an uncertain event, or
read original media.

## Select the exact transition

Supply the event ID and both canonical SHA-256 revision digests. The `to` digest
must identify the current retained head; `from` must identify its immediate
predecessor and equal that head's `supersedes` digest. A newer publication refuses
the old selection instead of silently following it. Comparing nonadjacent
revisions requires a separate implementation that preserves intervening changes.

```sh
fss explain --json --root /absolute/deployment \
  --principal principal:operator --event-id "$EVENT" \
  --question what_changed \
  --from-revision-digest "$FROM_REVISION" \
  --to-revision-digest "$TO_REVISION" \
  --view forensic --budget-tokens 16000
```

The selected view and context allowance cover the comparison, current protected
context, and structural support explanation together. The existing defaults
remain 1,800 tokens for `decision_diff` and 8,000 for `forensic`; the forensic
maximum is 16,000. A complete comparison that cannot fit returns a whole-result
refusal. It never drops changed fields, silently switches views, or raises the
requested allowance. Semantic token costs use the existing byte-based estimate,
not a measured model tokenizer.

Omitting `--question`, or explicitly selecting `--question why`, keeps the
existing explanation behavior and request identity. Revision selectors are
accepted only with `what_changed`. Combining this mode with historical `--at`,
learning selectors, `--custody`, calibration, or fusion options is refused before
admission. The separate `why_not` and `what_if` modes remain unimplemented here.

## MCP

Launch `fss-mcp` with the deployment and principal fixed by the operator:

```sh
fss-mcp --root /absolute/deployment --principal principal:operator
```

After the normal MCP initialization, call the existing `explain` tool with the
actual selected digests:

```json
{
  "event_id": "event:selected",
  "question": "what_changed",
  "from_revision_digest": "sha256:replace-with-exact-predecessor-digest",
  "to_revision_digest": "sha256:replace-with-exact-current-digest",
  "view": "forensic",
  "budget_tokens": 16000
}
```

`budget_tokens` is a JSON integer. Clients cannot override the root, principal,
capabilities, or privacy scope. CLI and MCP execute the same native comparison
and render the same response for the same selected scope.

## Complete comparison and proof identities

The native result is `fss.event_revision_comparison.v1` with these fields:

| Field | Meaning |
| --- | --- |
| `from`, `to` | Complete original `EventHypothesis` records, their exact revision digests, committed publication roots, and commit sequences. |
| `changes` | Every changed native field, in lexical order, with its complete `before` and `after` JSON values. Unchanged fields remain available in both complete records. |
| `anchorToken` | Current authority and effect-history token used for the comparison. |
| `policyDigest` | Exact adjacent-transition comparison policy. |
| `comparisonDigest` | Canonical identity binding the complete transition, publication witnesses, policy, and current scope. |
| `question`, `schema` | The explicit `what_changed` interpretation and versioned result identity. |

The comparison includes lifecycle, event kind, time interval, uncertainty text,
probability and calibration, zones, tracks, model receipts, and the full decision
path. Evidence changes compare complete edge records: relation, support flag,
failure domain, evidence class, and capsule/identity bindings. Two edges referring
to the same object digest can therefore differ materially.

The native `WhatChanged` receipt binds both revision digests, both independently
resolved publication roots, the complete comparison, and current history. The
response preserves current physical knowledge states, contradictory evidence,
possible worlds, residual alternatives, and unresolved obligations. A known
metadata difference does not promote an unknown physical claim to known.

Within the existing cognitive response, complete comparison values use the
`claim:event-changes:` prefix. Top-level scalars use their field name. Revision
wrapper fields use `from:<field>` or `to:<field>`; complete native revision fields
use `from:revision:<field>` or `to:revision:<field>`. Arrays append their exact
ordinal, and an empty array has an explicit unnumbered value. Complete change
rows use `changes:<ordinal>`. Each statement ends with `: ` followed by its whole
JSON value, allowing lossless reconstruction of the native comparison.

Commit sequences are canonical unsigned decimal strings. Native event revision
numbers and nanosecond endpoints retain the existing event schema's exact JSON
integer representation. Consumers must preserve integer precision rather than
rounding values through a floating-point JSON number representation.

## Read ownership and refusal behavior

One immutable native owner verifies the selected event lineage, each committed
publication manifest and canonical event payload, current deletion restrictions,
and the complete current authority/effect prefix. The owner remains alive while
the protected response is compiled and bounded; final verification uses the same
allowance. Final output serialization performs no new source read or authority
decision. The check observes custody changes and does not create an atomic
filesystem lease.

The default allowance is 256 MiB of metadata payload reads and 65,536 read
attempts, including final verification. Native callers may narrow these limits.
The frontend applies a cooperative 60-second deadline. The complete native
comparison and complete delivered response each have a 256 KiB ceiling, in
addition to the chosen view's context limit. Exceeding any bound withholds the
entire comparison.

Original source or model bytes are never opened. Missing original media does not
by itself invalidate a retained metadata comparison, and successful comparison
does not certify original-source availability. Missing, deleted, corrupt, or
changed selected revision metadata refuses. Refusals use only metadata already
observed during the attempted operation; they do not start a second diagnostic
read, disclose a partial comparison, or mutate deployment/session state.
