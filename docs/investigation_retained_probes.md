# Retained-source investigation probes

`fss investigate` and the MCP `investigate` tool can execute one explicitly selected,
already configured, session-owned retained-supervision subscription. They use AOP-006 and
return the registered `fss.agent_cognitive_envelope.v2` inside the normal response envelope.
The existing native evaluator owns discovery, custody, historical health, calibration,
failure-domain accounting, finite windows and durable report delivery.

This closes the operational gap between finding a retained subscription in session
orientation and actually using it through the agent interface. Losing the loose recipe or
restarting either transport does not lose its immutable configuration, pending report,
exact receipt, acknowledgement history, window progress or lifetime work charges.

## Select and run existing work

Use ordinary session orientation to find the owned subscription and its current authority
root. Configuration remains an explicit operator step through `fss-event supervise`;
the investigation operation cannot register or replace a recipe.

```sh
fss investigate --json --root /deployment --principal principal:local-operator \
  --session SESSION --transition probe --subscription probe:door \
  --authority-root sha256:CURRENT_AUTHORITY --view forensic
```

`probe` evaluates the selected native scope once if no result is pending. If a report is
already pending, the native owner revalidates its original source inventory and returns
the same historical report and receipt. Current validation and historical report authority
are reported separately. An unavailable source or changed historical health interpretation
refuses delivery, including sources excluded from the original decision after native reads.

The MCP invocation uses the same typed request, with the server's fixed deployment and
principal. Callers cannot override either scope:

```json
{
  "name": "investigate",
  "arguments": {
    "session": "SESSION",
    "transition": "probe",
    "subscription": "probe:door",
    "authority_root": "sha256:CURRENT_AUTHORITY",
    "view": "forensic"
  }
}
```

The illustrative digests above must be replaced with the exact 64-hex-digit identities.
The default `case` view retains its registered 5,000-token limit. A complete native report with
its actual context and proof objects can require the explicit `forensic` view (`AVIEW-004`,
16,000 tokens). Both transports accept only `case` or `forensic` for this probe profile; the
selected view is part of the command identity and every admission, pack, receipt and token charge.
There is no automatic promotion after a Case refusal, and choosing Forensic does not enlarge the
session's remaining lifetime allowance or its source-work bounds.
Every native probe action requires the live session's registered `CASE-WRITE` grant in addition
to the native supervision grants and private-property scope. Narrowing any pinned grant,
expiry, closure or interpretation-generation drift prevents further native work. A recipe
or a session label is never a source-read grant.

## Receipt and window lifecycle

| Transition | Required additional fields | Behavior |
|---|---|---|
| `probe` | None | One bounded fresh evaluation or exact pending replay with current custody checks. |
| `probe-inspect` | None | Existing progress and receipt metadata; no source read or native attempt. |
| `probe-ack` | `receipt` | Acknowledge that exact pending receipt after native validation; an exact last-ACK retry never consumes a newer report. |
| `probe-discard` | `receipt` | Explicitly abandon that exact receipt without treating it as acknowledged or as evidence of absence. |
| `probe-advance` | `window_index`, `after_receipt` | Advance an existing immutable schedule to the next adjacent cumulative prefix after the exact terminal receipt; no successor is evaluated. |

CLI fields are spelled `--receipt`, `--window-index`, and `--after-receipt`. MCP fields use
underscores. Window indices are zero based; advancement accepts the next index from 1
through 31, and native schedule continuity still determines whether it is permitted.

Pending delivery identities appear in typed H0 evidence handles with kind
`retained_supervision_delivery_receipt`. Native report and payload identities are separate
handles. Propositions preserve the pending status, historical basis, last ACK, last discard,
schedule progress, source validation and exact lifetime reservations. H0 handles identify
the proof; they do not promise a source-hydration endpoint or authorize access to footage.

No transition automatically acknowledges, advances, polls a successor, assesses a case,
contacts a camera/provider or executes an external effect. MCP notifications invoke none
of these operations.

## Attach a result to an exact case

An explicitly linked `probe` completes the investigation loop: it executes or revalidates the
selected retained subscription, then records its exact payload digest on one case hypothesis.
The case must already name that literal subscription in its `probes` set. The selected hypothesis
must match the immutable native recipe's hypothesis identifier. Case and native disclosure scope
must both be `private:property`, and the ordinary case owner checks the live session, mission,
current case predecessor, authority, deadline and capacity before source work.

First inspect the current subscription state with `probe-inspect`. Its progress proposition
contains the exact state digest, configuration identity, pending receipt and lifetime work.
Also inspect the case to obtain its exact current `revisionDigest`. Then explicitly select both:

```sh
fss investigate --json --root /deployment --principal principal:local-operator \
  --session SESSION --transition probe --subscription probe:door \
  --authority-root sha256:CURRENT_AUTHORITY --view forensic \
  --case case:door --expected sha256:CASE_REVISION \
  --hypothesis hypothesis:configured --side support \
  --subscription-state sha256:INSPECTED_NATIVE_STATE
```

MCP accepts the same `case`, `expected`, `hypothesis`, `side` and `subscription_state` fields
on its existing `probe` transition. All five are required together. `side` is the operator's
explicit choice of `support` or `contradiction`; the operation does not assess the hypothesis,
change its knowledge state, eliminate alternatives or conclude the case. The exact native state
is checked again while holding the native session journal immediately before a reservation or
action. A concurrent attempt, ACK, discard or schedule change therefore refuses the old request
before additional source work.

The native report and the case citation are separate durable commits. The citation records the
original pending receipt, report receipt, payload, configuration, native subscription state,
authority, fresh/replayed status and native journal root. Its own case revision, citation receipt
and commit root remain distinct. Journal recovery verifies the adjacent native Publish or Release
command and the exact state association. That establishes recorded native-owner custody at that
point; it does not independently re-execute the evaluator, interpret the opaque recipe or certify
present source availability. Native recipe/hypothesis semantics remain the native owner's assertion.

The successful response includes the actual case receipt identity as the typed H0 handle
`retained_probe_case_citation` and preserves its complete linkage metadata in the required context
pack. The report remains pending. Case citation never acknowledges or discards it, and a later
explicit ACK does not erase the historical citation.

## Recover an interrupted case probe

After a lost response, use the original case target with `probe-citation`:

```sh
fss investigate --json --root /deployment --principal principal:local-operator \
  --session CURRENT_READER_SESSION --transition probe-citation --subscription probe:door \
  --authority-root sha256:CURRENT_AUTHORITY --view forensic \
  --case case:door --expected sha256:ORIGINAL_CASE_PREDECESSOR \
  --hypothesis hypothesis:configured --side support
```

This lookup omits `--subscription-state`. It reads the exact historical citation under the current
reader's case, mission and privacy authority, including after the case has advanced or the original
report was ACKed or discarded. It does not require ownership of the original subscription, recover
its native configuration, revalidate sources, consume another native attempt, relink a case or revive
the original session's grants. It charges only its bounded metadata output. The returned pending
receipt describes citation-time custody; historical lookup does not establish current delivery state.

An absent citation is explicitly unknown about native execution: a process can stop after native
Publish or Release but before the separate case append. Repeating the original linked `probe` is
fenced by its old native state or case predecessor. Inspect the pending native report and current
case before deciding whether to select a new exact `subscription-state` for a deliberate, bounded
revalidation and link. An empty lookup never authorizes that retry automatically.

If citation committed but current-context admission, output quotation or durable output charging
later refuses, the known citation revision/root, native pending receipt and any committed token
charge remain visible in the refusal. The case and native owners retain their separate histories;
output failure does not roll them back or refund work.

## Complete decisions and bounded work

The cognitive projection preserves every evaluated window, native advice, reason,
knowledge state, likelihood/probability interval, common-cause cluster, calibration
qualification, leave-one-cluster counterfactual, native exclusion and historical health
warning. It also carries the current session's protected context and unresolved obligations.
Original detector spatial rows, numeric model internals and media stay behind their exact
native identities; this omission is explicit. Detector scores remain detector observations.
They establish neither class absence nor an independent actor association, synchronized
camera clocks, present camera health or an anytime-valid probability bound.

The response carries the actual registered `SemanticContextPack` and
`SemanticCompressionReceipt` objects for its final cognitive packaging, so the receiver can
verify the complete pair. The existing closed v1 response contract remains unchanged.
V2 receivers must read the required `contextPack.items`: it carries the complete, knowledge-tagged
native detail and protected current context. `epistemic.propositions` is an optional summary;
each entry exactly matches an item in that pack. Successful linked-probe deliveries leave this
summary empty to preserve the view allowance for the complete result and its citation. Pending/result/citation/charge state remains in the required pack, with its original
knowledge state and proof basis. Refusals and historical citation inspection keep their concise
summaries. This placement does not omit any admitted proposition or qualification.
The owner constructs and verifies the exact `SemanticContextPack` containing every admitted
proposition, warning, contradiction, invalidation, coverage qualification, unresolved obligation
and custody handle. No item is dropped at this step. The receipt's complete/lossless claim applies
only to that packaging; the earlier current-context receipt, its omission counts and priced
expansion limits remain explicit, as do the native/H0 source limitations above. Pack and receipt
digests bind the carried objects, without an invented hydration endpoint or availability claim.
Only this admitted probe response uses the additive probe presentation basis. Stored sessions,
workspaces, cases, subscriptions and ordinary orientation/follow paths keep their original basis.

Native source work uses the original subscription's cumulative attempt, stored-object-byte
and indexed-read ceilings. Each actual evaluation or revalidation reserves its complete
native allowance before work; failures and abandoned work are not refunded. Inspection,
discard and adjacent window advancement consume no new native attempt.

Successful investigation output additionally consumes the session's cumulative token
allowance. The reference quote counts UTF-8 bytes of the complete serialized response, including
its full cognition, actual context pack, receipt and outer-envelope overhead, divides by four
with upward rounding, and reserves 512 tokens for the final delivery-accounting witness.
The final serialized response must fit that committed quote. This is a quote rather than
measured tokenizer use; displaying refusal metadata does not charge a second quote.
The complete quote cannot exceed the explicitly selected view's registered maximum (Case 5,000;
Forensic 16,000) or the remaining session grant. The protected context is compiled for that exact
view; an unrelated Brief limit does not prevent an admitted probe response. The outer registered
budget vectors price output tokens only; zero entries for other dimensions mean unmetered, while
the cognitive budget keeps the exact native work and remaining session counters separately.

The final native delivery owner compares the exact session journal, subscription, live
authority and effect roots before durably charging the quote through the existing session
checkpoint and root pin. The response is released afterward. Explicit cold replay has a new
delivery quote. A crash or final-boundary failure can retain a charge without delivering
output; recovery reports the retained balance and never refunds or replays automatically.
Journal/configuration recovery, filesystem metadata, CPU and latency are additional bounded
work not fully metered by that quote.

The full response also has a 256 KiB byte ceiling. If the complete decision projection does
not fit, it is withheld with an explicit partial/refused outcome. The pending native report,
receipt and already spent work remain durable, and no implicit ACK occurs. Inspect the
subscription to choose an explicit next action. Failure output preserves known receipt,
ACK/discard/advance, case-link and token-charge progress; unobserved later state remains unknown.
If even a complete refusal context cannot be packaged, the registered outer envelope returns an
explicit partial outcome with `payload: null`, no compression receipt and bounded recovery metadata.
It withholds the incomplete cognitive context rather than presenting it as complete. Exact known
receipts and original lookup selectors survive this fallback, within the unchanged selected-view
ceiling. A fresh admitted complete context is required before making a decision.

## Verification scope

`supervisor_retained_contract::session::probe` exercises real retained native package
observations through fresh CLI and MCP processes: lost recipe recovery, exact replay,
durable cumulative token charging, explicit ACK and adjacent progression, notification
inertness, foreign/missing/stale scope rejection, deletion refusal and oversized complete
projection recovery. Ordinary AOP-003 Case requests remain refused. Parser tests keep recipe,
grant, budget-refill and mixed-action fields outside this interface.
The real-source fixture explicitly selects Forensic and compares every native inventory class, window knowledge state and
likelihood/probability interval with the required pack, validates the actual V2/pack/receipt schemas,
and checks actual serialized response bytes against the durably charged selected-view quote.
A separate default-Case overflow fixture preserves its unchanged ceiling and pending receipt.

The linked-case fixtures additionally cover exact predecessor/native-state admission, unchanged
competing hypotheses, cold CLI/MCP citation recovery after ACK and later case revisions,
published-but-unlinked interruption, explicit new-state revalidation and default-Case overflow
with retained case/native custody. Native journal tests cover append faults and forged historical
associations; the guarded deployment contract checks interleaving before the journal lock.

These fixtures verify the runtime path and custody boundaries. They do not qualify detector
accuracy, live devices or continuous surveillance coverage.
