# Hydrate one exact retained event

`fss query --target evidence-hydration` expands a selected retained event into a
native H0 identity or a complete H1 semantic synopsis. The same selector is
available through the MCP `query` tool. The operation uses an existing durable
session, verifies current metadata custody and commits the disclosure's token
charge and cursor transition before returning the artifact.

This is a reference implementation. It does not hydrate original media or
provide H2, H3 or H4. Retained uncertainty, contradictory evidence, pending
obligations and protected possible worlds remain visible.

## Select and open a session

Use the existing event query or explanation to select the exact event ID and
revision digest. Open a session at the current deployment head with enough
cumulative tokens for the intended deliveries:

```sh
fss query --target events --json --root /absolute/deployment

fss session open --json --root /absolute/deployment \
  --mission-text 'Inspect the selected retained event evidence' \
  --objective 'Preserve uncertainty and counterevidence' \
  --principal principal:operator --budget-tokens 100000
```

Keep the returned session ID, symbol-table generation and full current anchor
token. New sessions include the existing `CAP-AGENT-QUERY-001` and
`CAP-AGENT-EVIDENCE-HYDRATE-001` metadata grants. Older or narrowed sessions that
lack either grant remain refused; a transport request cannot upgrade them.
The local principal is an audit identity, not remote authentication.

## H0 identity and H1 synopsis

Set these shell variables from the actual retained selections and session:
`SESSION`, `GENERATION`, `EVENT`, `REVISION` and `ANCHOR`. They are exact
preconditions, not discovery hints.

```sh
fss query --target evidence-hydration --json --root /absolute/deployment \
  --principal principal:operator --session "$SESSION" \
  --generation "$GENERATION" --event-id "$EVENT" \
  --revision-digest "$REVISION" --anchor "$ANCHOR" --level H0
```

The outer response selects the explicit hydration presentation contract profile,
which declares durable charging and unsafe repetition. Existing sessions and
nested evidence objects keep their original reference basis and identities.

The response payload includes `descriptor`, `request`, `receipt`, `artifact`,
`cognition` and `admission`. Preserve `descriptor.descriptorDigest` and the
**complete JSON object** at `receipt.continuation`. For H1, set `DESCRIPTOR` and
`CURSOR_JSON` to those exact values:

```sh
fss query --target evidence-hydration --json --root /absolute/deployment \
  --principal principal:operator --session "$SESSION" \
  --generation "$GENERATION" --event-id "$EVENT" \
  --revision-digest "$REVISION" --anchor "$ANCHOR" --level H1 \
  --descriptor-digest "$DESCRIPTOR" --continuation "$CURSOR_JSON"
```

The outer response's continuation string identifies the cursor. It does not
contain enough information to resume. Pass the complete native object from the
receipt, serialized as a JSON string argument. Parsing preserves exact integers,
including privacy epochs, and rejects unknown fields, altered identities and
noncanonical numbers. Use a JSON implementation that preserves 64-bit integers.

The H0 quote is **5,000 tokens** and the H1 quote is **16,000 tokens**. These are
fixed descriptor prices, not measured tokenizer counts. The default
per-request ceiling equals that level's quote. `--budget-tokens` can set a
positive ceiling up to 16,000, but a ceiling below the level's quote refuses.
Both the requested ceiling and actual debit must fit the remaining lifetime
session budget. H1 never silently downgrades to H0.

A caller already holding the exact current descriptor may request H1 directly
without a continuation. Every successful direct request incurs another charge.
A progressive cursor can be consumed once, including across process restarts.

## MCP

Launch the existing stdio server with the deployment and principal fixed by the
operator. No media verification switch is required for this metadata profile:

```sh
fss-mcp --root /absolute/deployment --principal principal:operator
```

After the normal MCP initialization, call `query` with the actual selected IDs:

```json
{
  "target": "evidence-hydration",
  "session": "session:returned-by-open",
  "generation": "0",
  "event_id": "event:selected",
  "revision_digest": "sha256:replace-with-exact-revision-digest",
  "anchor": "replace-with-exact-current-anchor-token",
  "level": "H0",
  "budget_tokens": 5000
}
```

`generation` is a canonical nonnegative decimal string; newly opened sessions
start at `"0"`. Read it from the retained session rather than incrementing it. `budget_tokens` is a JSON integer.
For H1 add `descriptor_digest` and, when resuming, `continuation` as a string
containing the complete receipt cursor JSON. Root, principal, capability grants,
privacy overrides and source-verification fields are not accepted from clients.
The shared `query` tool advertises non-idempotent agent-state writes because this
target retains charges and cursor transitions.

## Evidence and failure behavior

The descriptor identifies the existing event revision URI and exact revision
digest. `artifact.payloadBase64` carries the complete native canonical H0 or H1
bytes, with their native payload and artifact digests. H0 uses the core identity
factory; H1 includes the event publication root in its proof set. Every nested
hydration anchor carries `privacyEpoch`, so a client can reproduce the exact
native identity without guessing a missing epoch.

H1 contains semantic assertions about the retained record. A known statement
that a record contains an unknown claim does not make the physical claim known.
The readable cognitive envelope retains the original claim states and names
counterevidence roots separately from supporting evidence. Metadata can remain
available after original media is missing; this does not certify source
availability, physical identity, continuous coverage or absence.

Only the existing agent session journal and its pin are written. Authority,
effect and retained object stores remain read-only. The same exclusive journal
owner records session aliases and atomically commits the token debit plus exact
cursor issuance/consumption. Workspace and other durable session state remain
in that journal; a separate cursor store is not introduced.

The supplied session generation, current anchor, revision and descriptor must
still agree. Changed authority or effect history requires fresh orientation and
explicit session rebasing; a cursor never silently follows the new head. Current
deletion and privacy restrictions apply during metadata reconstruction and final
revalidation.

One cumulative allowance of **256 MiB and 65,536 metadata payload-read attempts**
covers initial metadata admission, snapshot construction, retained event lineage
and final revalidation. Existing restore-fence, session journal and pin checks
retain their own independent bounds. No original media reader is opened. H0
canonical bytes are limited to 8 KiB, H1 to 64 KiB, and the complete protected
transport response to 256 KiB. Exceeding a bound refuses the whole payload.
The 60-second frontend deadline is cooperative; these observations do not create
an atomic filesystem lease or measure every filesystem syscall or CPU cycle.

A cancellation, changed object or rendering/output failure **after durable
admission** returns no artifact and preserves the known charge and consumed
cursor. A failed append or lost transport response can leave the outcome
uncertain: inspect the retained session journal before another direct request.
Failure rendering uses only an anchor already observed during the attempted
admission; it performs no additional metadata or media read. If no verified
anchor was obtained, it returns the ordinary unanchored CLI diagnostic.
No refusal implies a refund, an empty evidence result or permission to replay an
external effect.
