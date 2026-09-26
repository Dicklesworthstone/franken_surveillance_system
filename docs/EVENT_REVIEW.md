# Operator event review

Status: implemented reference behavior; not production-qualified. `fss-review` closes the
local operator loop after a recorded watch, package track, or corroboration pipeline has
published an event. It does not relabel sensor evidence as operator-verified truth.

## Inspect, preview, approve

Read the current event and its exact revision identity:

```sh
fss-review show --root "$ROOT" --site "$SITE" --event-id "$EVENT"
```

The result includes `revision_digest`, the original event payload, its publishing anchor,
core-permitted review dispositions, and any verified current operator-review statement.
A review readback preserves the original reviewer and rationale even when a different
principal reads it. Missing or altered review provenance is an error, not "no review".
The core-permitted dispositions are not permissions: preview rechecks authority and effects.

To reject a candidate the operator judges benign or erroneous, preview the exact successor:

```sh
fss-review reject --root "$ROOT" --site "$SITE" --event-id "$EVENT" \
  --expected-revision "$REVISION" --reason 'Owner reviewed the evidence and rejects the candidate'
```

Review the returned event, operator statement, provenance root, and `result.approval_digest`.
Repeat exactly the same command with `--approve "$APPROVAL"` to publish. Without that option,
there is no event or provenance write. Changing the actor, rationale, disposition or expected
revision changes the approval. A different current event revision makes a competing request
stale; no last-writer-wins replacement is performed.

`investigate` requests an `indeterminate` successor. `resolve` requests a `resolved` successor.
The existing core transition table is authoritative. In particular, `corroborated -> resolved`
is not a permitted direct transition. An operator who needs to reopen investigation and then
resolve must review and approve each permitted transition separately. There are no implicit
intermediate states, no urgent exception option, and no mutation of terminal events. An exact
retry of an already committed current review is verified and returned without republishing.

## Evidence and effect boundaries

The successor preserves the event identity, complete revision chain, original evidence,
classification, probability interval, capture bounds and uncertainty, zones, tracks and model
receipts. Open sensor-tamper risks remain in the lineage; resolving a case does not certify
restored sensor integrity. No classifier, sensor, provider or clock is invoked by review.

The added record is an attributed **operator assertion**. Rejection adds a `contradicts`
edge; investigation and resolution add a neutral `explains` edge. Neither adds sensor support
or another independent corroborating domain. A rejection does not automatically become a
training label or calibrated ground truth. The event decision continues to withhold external
effect authority.

Any deployment effect outside `verified`, `failed`, or `cancelled` blocks a **new** review,
even if it belongs to another event. This conservative deployment-wide guard is intentional
until narrower effect-to-event dependency admission is implemented. A new effect prepared
between preview and commit is checked again. Reviews never cancel an alert, reconcile a lost
acknowledgement, claim delivery, or erase an outstanding obligation. Use the owning effect
workflow first. An exact already-published retry does not perform a new lifecycle mutation.

The library uses separately registered review prepare/commit capabilities, matching site
universe and local I/O root, and explicit approval. Advisory agent-feedback authority is not
promoted into an event write. The CLI's boundary is the owner-authorized local process and its
filesystem access; `--principal` is an audit label, not remote authentication. Do not include
secrets, unnecessary identifying details, or raw media in the retained reason.

## Durability and compatibility

The statement and previous event root are published as a root-last provenance manifest,
then the guarded event publisher appends the successor. A cancellation after provenance but
before the successor leaves the old event current; rerunning the same exact approved request
can finish it. A visible but not-yet-ledgered provenance root is reconciled before successor
publication. Post-event-commit cancellation still reports the committed event. A completed
retry verifies retained provenance instead of silently reconstructing missing custody.

Approvals bind the predecessor event's original publishing anchor, not the whole deployment's
latest head. Unrelated ledger appends do not invalidate them. Event changes and the effect
guard still invalidate new admission. A provenance-only abandoned review is not an event
revision and does not replace canonical event state.

The existing event schema and past revisions are unchanged. Existing event readers can see
the successor through current authority; producers with an obsolete predecessor cannot
replace it. Review roots consume the deployment's existing bounded root capacity and remain
subject to existing retention/deletion semantics. This is not a new hold or an undeletable
personal-data store. A deleted review statement is not regenerated on retry; retained event
history may still name its digest.

Bounds: 256 revisions, 65,536 authority batches, 32 MiB cumulative event-history payloads,
4,096 effect operations, 8 KiB per statement, and 512 UTF-8 bytes per rationale. Exceeding a
bound refuses the complete operation. These are finite reference limits, not performance SLOs.

## Verification and remaining work

```sh
cargo test -p fss-reference --lib event_review
cargo test -p fss-cli --bin fss-review
cargo test -p fss-cli --test event_review_cli_contract
python3 crates/fss-reference/tests/fixtures/event_review_model.py
```

The Rust cases exercise real deployment journals, state/authority restrictions, cold reopen,
competing approvals, retained readback, cancellation cuts, a real prepared effect, and a
generated-JPEG-to-watch-to-review workflow through the native binary. They were authored but
not executed in the authoring environment: Rust compilation, tests, rustfmt and Clippy remain
unverified because no Rust toolchain is available.

The independent Python model passed 5,184 state/action/interleaving/publication-cut/effect/
foreign-append scenarios plus a late effect guard. It is not execution of the Rust code or
proof of filesystem durability. Remote authentication, full agent/MCP protocol exposure,
terminal-state corrections, automatic adjudication, and effect reconciliation remain open.
