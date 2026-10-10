# Process a captured HTTP history into retained recording proposals

`fss-watch-http-history` connects an exact durable reconnect history to the retained
recording pipeline. It verifies the selected history and original responses, imports
every generation that contains complete JPEGs, and runs native streaming zone-entry
analysis independently over each imported recording. Its output includes exact
`fss-event watch --stream-watch` commands for separately approved proposals.

This completes the bounded operator workflow:

1. Capture explicitly reserved generations with `fss-capture-reconnect --durable-history yes`.
2. Save the acknowledged `(session, root, connections)` history pin independently.
3. Preview and approve the exact history-to-recording operation with explicit camera and
   capture-time bindings for every selected generation.
4. Review the native proposals and run only the event commands you separately approve.

The processor is an offline, finite operation. Capture, original-byte disclosure,
destination retention and event publication remain separate permissions. Running the
processor never connects a camera, advances a capture history or publishes an event.

## Capture and select an ended history

See [the durable capture workflow](HTTP_RECONNECT_HISTORY.md) for complete route,
generation, original-retention and approval options. `history_prepared` is an expected
root whose publication is still unconfirmed. `history_durable` acknowledges the exact
durable root before the recorder re-verifies it and releases the next generation.

Select a saved history pin. Do not infer a latest head from directory contents. The pin
commits the native order of completed connection boundaries, including failed attempts
with no response bytes. A reserved next generation is not evidence it was connected.
An unfinished current wire prefix stays outside ended history; this tool does not
invent a terminal boundary to include it. An independently saved prepared pin whose
acknowledgement was lost can also be supplied: the complete cold verifier must prove
that exact root is actually durable before processing begins.

The original archive and retained deployment must be separate, non-nested directories.
The archive must already exist. The existing local publisher obtains its normal
exclusive lock and performs recovery synchronization, so simultaneous capture into the
same archive is not supported by this synchronous workflow.

## Preview the exact processing plan

Use one `--binding` for each selected connection, in strictly increasing native
generation order. The fields are:

```text
GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS
```

For a saved two-connection history containing generations 40 and 41:

```sh
fss-watch-http-history \
  --archive /srv/fss/front-camera-originals \
  --root /srv/fss/retained-site --site site:home \
  --principal principal:local-operator \
  --history-session "$HISTORY_SESSION_SHA256" \
  --history-root "$HISTORY_ROOT_SHA256" --history-connections 2 \
  --binding 40,sensor:front,stream:front-40,1791504600000000000,1791504000000000000,1000000,10 \
  --binding 41,sensor:front,stream:front-41,1791505200000000000,1791504600000000000,1000000,10 \
  --interpretation gray --zone driveway:0,0,640,480 \
  --owner-authorized yes --read-originals yes --retain-originals yes \
  --max-frames-per-generation 4096 \
  --max-bytes-per-generation 67108864 \
  --max-history-reads 8192 --max-history-bytes 536870912 \
  --max-work 1000000000000 --max-framing-work 10000000000 \
  --work-units 10000000000 --timeout-ms 600000 \
  --screened yes
```

The first invocation performs pure argument and reservation validation. It opens no
files and reads neither clock nor network. Its JSON preview includes the exact pin,
ordered camera/time bindings, native watch configuration, whole-invocation reservation
and `approval_digest`. Review those values, then repeat the same command with:

```text
--approve-import sha256:<the preview's exact 64-hex-digit approval>
```

Changing the history, binding, destination, site, principal, interpretation, zone,
threshold, screening choice, timeout or any admitted limit changes the approval. The
library plan uses `fss.http_history_watch_plan.v1`; the CLI additionally binds its paths,
principal and runtime allowances in `fss.http_history_watch_cli_plan.v1`. Neither digest
is an event approval or a remote camera authentication credential.

Capture timing is explicit even for empty attempts. The native receive clock is a
monotonic acquisition observation, and it is never converted to wall-clock capture time.
Every imported frame uses the existing file-import interval calculation, retains
`capture_time_label: operator_assumption`, and must finish no later than the explicitly
declared receive time. The worst admitted frame endpoint is checked during preview, so
capture hints must cover the full reserved frame range. The sensor binding selects the
target sensor's current privacy policy; historical capture or mask metadata cannot
override that current policy.

## Read the result and review proposals

The complete result uses `fss.http_history_watch_report.v1`. `history` names the exact
verified pin, `reservation` gives the fixed whole-invocation ceilings, and `generations`
contains every selected native connection in order. Each entry retains its original
source scope, exact wire prefix, native completion/failure class, camera/time binding,
and one explicit processing status:

| Status | Meaning | Retained import and watch result |
| --- | --- | --- |
| `analyzed` | Complete original JPEGs were imported and the complete admitted recording was analyzed. | `import` and native `watch` are present. |
| `empty_response` | The native connection ended without any retained response bytes. | Both are `null`. |
| `no_complete_jpeg` | Native replay reached the selected nonempty prefix without a complete original JPEG. | Both are `null`. |

Malformed HTTP/MIME, missing original bytes and resource exhaustion remain typed
failures. They do not become `no_complete_jpeg`, skipped connections or quiet-scene
claims. The archived native outcome is separate from import ending: a retained import
can cover a valid incomplete prefix, and HTTP/MIME completion does not prove physical
coverage or camera health.

The importer first completes or reconciles every selected recording. Analysis then
runs against one shared deployment basis. Each generation has a fresh background
model and tracker; track IDs never join objects across reconnects. Within a generation,
the streaming walker preserves state across the former 128-frame boundary and can
report a late observed zone entry anywhere in the complete admitted recording.

Each analyzed entry includes the unchanged native long-watch JSON. Candidates remain
unclassified, indeterminate, uncalibrated, single-sensor observations with `[0, 1]`
probability, a Hold decision and no alert or absence authority. Foreground tracking does
not assert personhood, identity, intent, a physical arrival or uninterrupted occupancy.

An eligible candidate's `publish_command` is a complete `fss-event watch --stream-watch`
rerun using the same import, frame range, zones, thresholds, decoder limits, streaming
ceilings and screening policy. It also carries that candidate's exact `--approve`
digest. Review the observation and source, then execute the command if you want to
publish that event. The event owner recomputes the analysis and rechecks source,
privacy, principal and approval before publication. An exact event retry does not
duplicate the event. The history processor itself accepts no event approval.

`--screened yes` sends the current privacy-masked pixels through the existing
conservative sensor-health screen. Findings or incomplete screening keep diagnostic
results but suppress publication commands. No historical mask or pre-mask pixels
reach foreground processing, tracking or health screening. `--tolerate-decode-refusals
yes` opts into the native typed-gap policy; any allowed gap resets perception instead
of joining a track across unavailable evidence.

## Bounded work and restart reconciliation

The complete history has at most 32 connections, 8192 original reads and 512 MiB of
original source. Each generation imports at most 4096 frames and 64 MiB of original
response bytes, with an independent 64 MiB reconstructed-stream ceiling. The default
per-generation frame ceiling is 128; selecting a larger bounded recording requires
an explicit larger reservation.

Every generation receives its fixed native watch allowance before history I/O. Unused
work is never transferred from one connection to another. The preview reports checked
sums for frames, original bytes, source reads, luma samples, assignment work, JPEG work,
trace bytes and complete JSON bytes. Across the selected history, native trace storage
is capped at 256 MiB. The combined report has a separate maximum of 32 MiB plus 64 KiB.

| Option | Scope |
| --- | --- |
| `--max-work` | One history-verification and import work allowance for the complete invocation, including final history re-verification. |
| `--max-framing-work` | One native HTTP/MIME parser allowance shared across all selected generations. |
| `--work-units` | Fixed native JPEG decoding allowance per generation; copied exactly into event reruns. |
| `--stream-read-bytes` | Fixed native source-read allowance per generation, including HTTP original verification. |
| `--stream-pixel-budget` | Fixed luma-processing allowance per generation; screening has its native separate counter under the same ceiling. |
| `--stream-assignment-work` | Fixed tracker-assignment allowance per generation. |
| `--stream-trace-bytes` | Fixed complete native trace ceiling per generation. |
| `--max-report-bytes` | Complete combined report bound. |
| `--timeout-ms` | Cooperative deadline for the complete approved processing operation. |

The CLI checks its timeout at source/import boundaries and before and after each whole
generation's analysis. Native reads and frames remain `ReplayCx`-cancellable and
work-bounded inside that analysis, but the CLI timer cannot preempt a single analysis.
An expiry refuses subsequent processing and the final result; it does not undo imports
that were already durably committed.

There is no replacement progress journal or automatic acquisition restart. Each import
has the existing deterministic source/camera/timing identity and root-last custody
publication. If processing stops after one import, that import remains durable. Rerun
the exact approved command: the importer verifies and reuses completed records, then
continues missing imports. A failure later in analysis may follow durable completion
of all imports. A lost final output may likewise follow successful custody publication.

Exact retries never repair or reacquire damaged original custody behind a visible root.
The target's copied original HTTP bytes, wrappers, partial tails, source maps and
reconstructed JPEGs stay in the existing deletion closure. Damaged copied originals
refuse retry and event publication even when reconstructed JPEG chunks remain intact.
The separate source archive is verified again before the processor returns its complete
report. A later standalone retained event replay can work without that external archive
because the target import contains its own source closure.

## Native verification

```sh
cargo test -p fss-reference --test http_history_watch_contract --locked --offline
cargo test -p fss-cli --bin fss-watch-http-history --locked --offline
```

The contract target creates real local TCP responses, captures them through the native
durable reconnect owner, and tests a 200-frame late entry in the second generation,
cold exact retry, honest empty and incomplete responses, explicit mappings, current
permission, cancellation between imports, source damage, copied-original damage,
whole-history work exhaustion, privacy masks and conservative screening. These fixtures
establish executable reference behavior; they do not qualify a camera, deployment,
capture clock or detector's real-world accuracy.
