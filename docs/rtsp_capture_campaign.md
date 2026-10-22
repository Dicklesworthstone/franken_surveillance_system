# Bounded native RTSP capture campaigns

`fss-capture-rtsp reconnect --continue-after-success yes` runs a finite sequence of
independently approved native capture sessions. Unlike ordinary reconnect mode,
it can start the next session after a successful capture. It reuses the native
AVC/HEVC recording, root-last archive and independent recovery-pin owners.

This is not an always-on daemon or a gap-free recording claim. Every successor
starts a new generation and its own receive/decode clocks, archive and pin journal.
The time between sessions is not filled in, and no campaign result certifies
scene coverage or absence.

## Plan before opening a camera

Start from an owner-authorized capture command described in `rtsp_capture_cli.md`.
Keep its exact peer, codec, media selection, timing evidence, credentials policy
and per-session limits. Use separate new archive and pin path prefixes, then add:

```sh
fss-capture-rtsp reconnect \
  --root /owner/private/porch --pins /owner/recovery/porch \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/main --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch \
  --generation 1 --ingress 1 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --timing-evidence "$TIMING_EVIDENCE" --journal-id "$JOURNAL_ID" \
  --frame-duration-ticks 3600 --stop-after-pictures 50 \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --max-attempts 3 --retry-delay-ms 250 --retry-max-delay-ms 5000 \
  --continue-after-success yes
```

The digest variables must contain the operator's nonzero SHA-256 identities.
The example cadence is 25 pictures per second on the explicitly declared 90 kHz
media clock. It is not an inferred capture timestamp. The command does not
resolve camera hostnames or discover peers; its literal IP and route are exact.

Without `--approve`, preview is pure: no files, credentials, clocks or sockets
are opened. The preview enumerates all possible child sessions and their aggregate
source, storage, output, capture/drain and backoff ceilings. Review it, then repeat
the exact command with its outer `--approve sha256:HEX` value.

A single-session approval, an ordinary reconnect approval, or a stale campaign
approval cannot authorize these additional sessions. Omitting the new option keeps
legacy reconnect approval bytes and stop-after-first-success behavior unchanged.
Only the explicit value `yes` is accepted.

The example creates these independent destinations as each attempt starts:

```text
/owner/private/porch.attempt-0001
/owner/private/porch.attempt-0002
/owner/private/porch.attempt-0003
/owner/recovery/porch.attempt-0001
/owner/recovery/porch.attempt-0002
/owner/recovery/porch.attempt-0003
```

Parents must already exist. Existing destinations are never overwritten or skipped
to find an unused ordinal. Each native owner retains its alias/separation checks.
Pin journals must be protected independently from the footage. Original local
custody remains unencrypted; this feature changes no privacy or retention policy.

## Completion and continuation

`--stop-after-pictures` remains a per-attempt target. `--max-attempts` includes both
successful and unsuccessful attempts, with a hard limit of 16. Backoff is bounded
and applies between successful sessions as well as permitted failure retries.
No timer, worker pool, media queue, runtime or unbounded retry is introduced.

The native owner must observe a final archive snapshot, no pending control request,
no unsettled storage obligation, and every collected picture durably retained.
The controller additionally checks the exact approved picture count before a
successful session may admit its successor. Underfilled, overfilled, empty or
unsettled nominal successes cannot advance a campaign.

A campaign is complete only when every planned attempt settles successfully.
An early EOF followed by later successful captures remains a partial campaign:
the original failed attempt and durable prefix are retained, the final command
fails, and later footage does not erase the earlier shortfall. A current fatal
error takes precedence as the returned error while the first failure remains in
the terminal report.

Failure retries retain the existing rules. Typed transient connect failures and
drained source-end shortfalls may retry. Progress-stall retries additionally
require the original `--progress-timeout-ms` opt-in and a normal archive drain.
Authentication, revoked credentials, protocol/timing errors, exhausted budgets,
output failure and unsettled archive work do not become retryable because a
successful session preceded them.

The native `attempt_finished.complete` field continues to describe the native
media result. Campaign fields separately expose `settled_success`,
`continuation_blocked`, `continuing_after_success` and `next_attempt_planned`.
This preserves an observed native completion without confusing it with permission
to continue. Terminal campaign output includes successful/unsuccessful counts,
first failed ordinal, first/current error identities and total durable pictures.
`continuity_across_attempts` and `absence_certifiable` remain false.

## Preserve and replay each epoch independently

Preserve complete stdout JSONL and both stores for each attempt. Each native
`catalog_published` row identifies its exact catalog slot/root, decode clock and
source generation. Import it with `fss-import-rtsp` under a separately reviewed
import approval, using that epoch's receive clock, not the original pre-campaign
receive-clock identity. The original capture plan lists the derived receive clocks.

Opt in to `--history-root NEW_DIRECTORY` to retain durable campaign metadata,
including failed and empty attempts, without relying solely on stdout. The
[durable campaign history guide](rtsp_campaign_history.md) describes its separate
approved limits, independently saved pins and exact read-only inspection. Keep
the native stores and complete native reports for their full custody details.

With a saved history pin, `fss-watch-rtsp-campaign` can import and analyze all
catalogued attempts under one reviewed operation. It validates the exact complete
catalog mapping, keeps failed/empty/unknown attempts visible, and gives each
recording independent native detection and tracking state. The
[campaign watch guide](rtsp_campaign_watch.md) describes its explicit per-attempt
bindings, aggregate budgets and retained-custody rerun commands.

An imported catalog retains its original recording closure. `fss-file verify` and
native range decoding must continue to work when the original capture archive is
offline. Import retries preserve the same imported identity and do not append
duplicate ledger/effect records. Import and replay do not rewrite recovery pins.

## Explicit cold continuation after restart

A process restart never silently adopts a history directory. To continue a finite
campaign after a successfully finished attempt, repeat the **original reconnect
options and original history limits** and add all four coordinates from the
independently saved `attempt_finished` receipt:

```text
--continue-history-approval sha256:...
--continue-history-plan sha256:...
--continue-history-root-digest sha256:...
--continue-history-records N
```

Preview again and approve the newly returned outer digest. The original capture
identity and every child attempt identity remain unchanged; the new continuation
approval separately binds the exact saved finish pin. The selected prefix must
contain only settled-success attempts, have no campaign terminal, and end with
`next_attempt_planned=true`. Start-only tails, failed/retry prefixes, terminal
campaigns, changed plans, changed writer limits and partial coordinates refuse.

The existing history graph is reopened and reverified through the live publisher
before any new camera session. Verification uses a fresh `--history-work` account;
historical time, work and provider allowances are never reconstructed, refunded or
made spendable again. The approved inter-attempt backoff is conservatively repeated
before the next predeclared attempt, because a dead process cannot prove whether it
already completed that wait. Previously completed archives are not reopened as live
capture destinations and no generation, clock or path is reused.

This first operator continuation mode intentionally resumes only a clean
settled-success prefix. Retry-after-failure continuation remains unsupported rather
than losing the earlier failure when reconstructing terminal campaign statistics.

## Explicit offline recovery

Repeat the original campaign options, including `--continue-after-success yes`,
remove the capture approval and add `--recover yes`. This selects the existing
metadata-first recovery preview, with no camera or credential access. Its separate
approval binds observed stores, journal tips and the exact original capture plan.
Use `--recover index` only for the separately approved source-reading catalog-index
operation after unsettled work is resolved. Independent `--minimum-pin-anchors`
continue to fence the listed original attempt ordinals.

Recovery does not start new sessions, join epochs, infer that missing stores never
existed, or convert recovered footage into a completed campaign. On an output
failure or lost reply, preserve all stores and preview the current recovery state
again. Do not treat a truncated JSONL record as an acknowledgement.

## Native regression checks

Run the existing pinned native entrypoints:

```sh
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-cli --bin fss-capture-rtsp
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-cli --test capture_rtsp_cli --test capture_rtsp_reconnect_cli
```

Campaign controller cases cover exact approval separation, native settlement,
under/over-capture, partial completion, fatal failure, cancellation, output failure,
recovery admission, one-session and sixteen-session limits. The real-process cases
exercise successful and partial campaigns, independent catalog import and cold
native AVC replay, authentication after success, and preservation of existing
successor custody. They reuse owned loopback camera fixtures and the real native
binaries; they are not camera/site qualification or DSR release authority.
