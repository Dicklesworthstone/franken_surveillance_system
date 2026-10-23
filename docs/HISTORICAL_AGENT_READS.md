# Inspect an earlier retained decision

`fss query` and `fss explain` accept `--at <anchor-token>` to select an exact retained
authority and effect-history prefix. Use an `anchor:...` token returned by an earlier
`fss orient`, query, or follow response. The full token binds the deployment lineage,
commit position, and effect journal; a numeric commit alone is not sufficient.

```sh
fss query --json --root /owner/site --at "$ANCHOR" --zone door
fss explain --json --root /owner/site --at "$ANCHOR" \
  --event-id event:example --view forensic
```

The query selects the event revisions and filters that existed at that prefix. Explain
uses the event's latest committed revision **at the selected prefix**, even if a later
revision now supersedes it. An event published later is reported as absent from that
prefix's event index, which does not establish physical absence.

Every historical answer identifies both its selected token and the current history head
against which it was verified. Event hypotheses, coverage, effects, and obligations in
the answer describe that earlier prefix. Run `fss orient` at the current head before an
operational decision. These reads expose metadata and read affordances; they grant no
effect authority or media disclosure permission.

## Current-head checks and pagination

`query --anchor <token>` retains its existing meaning: require that the **current** head
still matches the token, otherwise refuse. `--at` explicitly selects history. The two
options are mutually exclusive, so a stale current-head precondition cannot silently
become a historical read.

For a paginated historical query, repeat the same `--at`, filters, principal, and page
size with each returned continuation:

```sh
fss query --json --root /owner/site --at "$ANCHOR" --max-entries 8
fss query --json --root /owner/site --at "$ANCHOR" --max-entries 8 \
  --continuation "$CONTINUATION"
```

The selected event index remains fixed when later commits arrive. Omitting `--at` does
not make a historical continuation valid at the new current head. Foreign, forged,
unretained, and future anchor tokens refuse with `ERR-AGENT-RESNAPSHOT-001`; no empty
success is substituted.

## Deletion and custody apply now

Historical reads apply deletion records from the entire **current** committed history.
Selecting a prefix before deletion never restores source access. Historical event
metadata can retain references to deleted evidence, with the deletion still visible.
Missing or corrupt required authority objects fail the read.

To check the bytes that remain available **now** for the selected historical event
publication, explicitly request custody:

```sh
fss explain --json --root /owner/site --at "$ANCHOR" \
  --event-id event:example --view forensic --custody yes
```

The existing bounded custody walker rehashes the selected publication closure, observes
current deletion denials and tombstones, then revalidates the exact selected prefix and
current head. A changed head refuses the checked answer. This is a sequential current
byte observation, not a reconstruction of past custody or an atomic filesystem snapshot.
Historical scope consumes the existing explanation context allowance; no view or budget
is widened automatically.

## MCP parity

The `query` and `explain` tools accept the same optional `at` string and return the
canonical CLI response unchanged:

```json
{"name":"query","arguments":{"at":"anchor:...","zone":"door","max_entries":8}}
{"name":"explain","arguments":{"at":"anchor:...","event_id":"event:example","view":"forensic","custody":"yes"}}
```

Replace `anchor:...` with a complete returned token. The MCP server's fixed deployment
root and principal still apply; `at` does not override either scope.
