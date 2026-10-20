# Bounded native dwell continuation

`fss-event watch --stream-dwell --dwell-step-frames N` advances a completed retained MJPEG
recording by at most `N` new source positions, then publishes an immutable computation
checkpoint. The next invocation can reproduce that checkpoint and continue the same native
foreground model, tracker, capture-clock checks and sampled-dwell accumulator. An episode
spanning multiple steps has the same final analysis, proposal and event identity as the
existing whole-recording MJPEG analysis.

This closes the previous restart-at-frame-zero analysis boundary for scheduled work: a live
library owner processes only new positions on each successful advance, and an interrupted
process can reconstruct its last retained prefix with explicit extra-work admission. Durable
checkpoints contain a recipe and native trace. They never deserialize caller-supplied tracker,
foreground or decoder state.

## Run a recording in bounded steps

Use the same completed import, explicit image interpretation, image-coordinate zone and dwell
rule as ordinary [whole-recording dwell](long_recording_dwell.md). For example:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed MJPEG import identity}" \
  --interpretation gray --zone porch:100,80,400,300 \
  --stream-dwell --segment-count 300 \
  --dwell-for-ns 20000000000 --dwell-max-gap-ns 100000000 \
  --dwell-min-observations 3 \
  --dwell-step-frames 128
```

The first successful response has schema `fss.incremental_dwell_progress.v1`, status
`checkpointed`, `next_segment: 128`, `remaining_segments: 172`, and exact `checkpoint_digest`
and `checkpoint_root` values. The explicit step option authorizes retention of that derived
checkpoint. It does not authorize an event.

Execute the response's `continuation_command`. It preserves the original request and adds:

```text
--dwell-checkpoint sha256:CHECKPOINT_BODY
--dwell-checkpoint-root sha256:CHECKPOINT_ROOT
--dwell-restore-max-frames 128
```

These are two exact immutable pins and a separate admission to replay at most 128 prior source
positions. No mutable “latest checkpoint” file or unpinned automatic fallback is consulted.
Each response supplies a replacement command naming its newly retained prefix. In the example,
the second process reconstructs 128 old positions and advances 128 new ones. The third
reconstructs 256 and advances the final 44.

When the declared full range completes, the wrapper has status `complete` and includes
`event_report`, the existing `fss.long_dwell_report.v1` with its complete qualifying episodes.
If detector options were requested, its terminal trained stage must also succeed before this
complete response is emitted.
Review an episode's `event_report.candidates[].publish_command` to publish its exact proposal.
That command reconstructs the complete checkpoint and passes the original event approval
through the existing guarded publisher. A completed checkpoint advances zero new positions.
An exact event retry reports `already_published` and appends no duplicate event.

An incomplete range has no `event_report`. Supplying an event approval when the requested step
cannot complete the range is refused before native work or checkpoint publication. A qualifying
but still active episode is not prematurely finalized at an arbitrary scheduling boundary.

`--report-out PATH` writes the complete progress wrapper using the existing create-only export
owner. The emitted continuation omits the old output path so it can be executed directly.
Checkpoint or event publication can finish before a later report-file/stdout failure. Retry
the exact request to recover the same durable result.

## Finish with trained classification

Add the existing verified detector options to the bounded-step command:

```text
--detector-package /path/to/model.fmpk
--detector-digest sha256:EXACT_PACKAGE_DIGEST
--detector-max-inferences 8
--detector-frames-per-track 3
```

Partial responses explicitly report `detector_stage: "deferred_until_complete"` and the
effective `detector_request`: inference allowance, selected frames per episode, association
threshold and optional score override. They do not open the package or run the model.
The exact package path, digest and every explicit detector option remain in the emitted
`continuation_command`. Supply the pinned package at that path before the final step.

On the final step, the native owner first retains the completed temporal checkpoint. It then
verifies the exact package and classifies only actual observations belonging to qualifying
episodes. The final response reports `detector_stage: "complete"` and includes the existing
trained `event_report.detector_cascade`, recipe, selected/refused/skipped samples, model work
and proposal identities. A zero-episode stage still verifies its package but executes no
inference; stage completion does not itself mean that a model was invoked. Requests without a
detector preserve the original progress output and omit both detector fields.

Classification spends the remainder of the original temporal scan's source-byte, pixel and
JPEG allowances. It does not restart foreground detection or tracking, and it cannot obtain a
fresh full-scan budget by reopening a checkpoint. All episodes share the explicit inference
allowance. The wrapper's `logical_scan_work` remains temporal work; the complete native event
report includes the added classifier costs.

The checkpoint pins the temporal request. Detector options are a separate explicit terminal
request preserved by the continuation command; changing those options does not rewrite the
temporal prefix. The resulting trained recipe, analysis and proposals bind the exact verified
model, selection policy and full native execution limits. An old untrained approval cannot
publish the trained candidate. Review and use the new complete report's `publish_command`.

A missing package, wrong digest, exhausted original allowance or native classifier refusal
leaves the retained temporal checkpoint intact and emits no successful report or event.
The failed command returns no new checkpoint pins. Repeating the prior saved continuation
reconstructs its admitted prefix and repeats the final temporal suffix before exact checkpoint
reuse. A separately known completed checkpoint advances zero new positions, while still
reporting its cold-prefix reconstruction. An exhausted original allowance requires a new
temporal request with sufficient limits; it cannot be raised while resuming the old checkpoint.
Each terminal attempt owns its classifier work separately; a failed attempt's extra work is not accumulated
into the immutable temporal checkpoint. Callers must account for those retry costs, in addition
to the explicitly reported cold reconstruction. A successfully trained in-memory report cannot
run the terminal stage again.

Publication uses the existing guarded event owner and retains the exact model archive and
native replay recipe. After publication, `fss-replay-dwell inspect/verify` can replay this MJPEG
event from retained custody after the loose recording and model files are removed. Reusing an
event publication command still requires its explicit model input. The event remains
Unclassified, Indeterminate and Hold; these annotations grant no alert or class-absence
authority.

## Calibrated advice from a completed checkpoint

After the terminal trained stage succeeds, its complete response supplies the native
`event_report` and an exact `continuation_command`. Author a
[dwell-scoped fusion profile](long_dwell_class_fusion.md) from
`event_report.analysis_digest`, `event_report.analysis_root` and
`event_report.detector_cascade.recipe_digest`, using explicit applicable labelled counts.

Execute that completed checkpoint's continuation command with the same detector options and
append the exact profile pins:

```text
--fusion-profile dwell-profile.json --fusion-digest sha256:EXACT_PROFILE_FILE_DIGEST
```

The checkpoint must already cover the full original range. A fresh incremental request or a
partial prefix is refused, even if its selected step could finish the remaining positions.
Finish and retain that temporal scan in a separate invocation first. Fusion also refuses
event approval, health/coverage retention and incremental health screening.

This invocation opens the exact retained checkpoint, reconstructs its complete prefix under
`--dwell-restore-max-frames`, finishes the native report and executes the requested terminal
classifier under the original remaining scan ceilings. The fusion adapter then consumes those
class records without another inference pass. It processes no new temporal positions, appends
no checkpoint and publishes no event. The response keeps the original checkpoint pins, reports
`new_source_positions: 0` and exposes the full cold reconstruction cost separately.

The profile file digest and whole-dwell scope are checked before checkpoint/source or model
work. After checkpoint completeness is admitted, the package is verified before cold replay.
Native reconstruction must reproduce the exact checkpoint. After reconstruction and
classification, the complete trained analysis, source root and detector recipe must match the
profile. Source custody, current privacy, principal and the current analysis basis are
revalidated for advice and immediately before each output delivery. Missing custody, a changed
recipe or exhausted original allowance refuses the complete result.

The response adds `event_report.calibrated_class_advice`, using the existing version-four
dwell advice schema. Native episode/proposal fields and publication hints remain intact; the
continuation and approval commands omit fusion so publication stays a separate operation.
The complete progress response with advice, including its final newline, is bounded to 2 MiB.
Existing model-free and trained progress responses retain their original 1 MiB plus 16 KiB
bound. Calibrated advice adds no event, absence, continuous-occupancy or alert authority.
Each explicit repeat pays cold reconstruction and terminal-classifier costs again; a checkpoint
does not cache trained inference or make repeated observations independent.

## Admission and accounting

| Option | Contract |
|---|---|
| `--dwell-step-frames N` | Admit at most 1–65,536 new source positions in this process. The final step stops at the declared range end. |
| `--dwell-checkpoint DIGEST` | Pin the exact canonical checkpoint body. Requires the root pin. |
| `--dwell-checkpoint-root DIGEST` | Pin the exact published, ledgered checkpoint graph. Requires the body pin. |
| `--dwell-restore-max-frames N` | Explicitly admit 1–65,536 old positions for cold reconstruction. Required only with checkpoint pins. |

The complete original temporal request is pinned: import identity/root/manifest/completion anchor,
selected range, sensor, current privacy digest and generation, actor and site, image
interpretation, zones, foreground and tracker settings, dwell rule, refusal behavior, native
decoder identity, analysis policy and every original decoder/read/aggregate ceiling. A changed
request or privacy generation cannot resume a checkpoint. The step size itself is scheduling
admission and may change between invocations.

The original whole-analysis JPEG, source-byte, pixel, assignment and trace allowances remain
spent after a step or a cold reconstruction. There is no per-checkpoint refill. A lower original
allowance cannot be evaded by repeatedly saving and resuming.

Cold replay consumes additional real work. `cold_restoration_work` reports all seven native
prefix counters spent in the current process; fresh starts report zeros. `logical_scan_work`
reports the single cumulative logical analysis, including the reconstructed prefix once.
`new_source_positions` distinguishes newly processed positions from the prefix. A source
position with an explicitly tolerated decode refusal still consumes a position, even though
it is not a successfully decoded frame.

The library's `DwellRestoreLimits` also requires separate conservative native execution
admission: all original stored scan ceilings must fit its `execution` limits before decoding.
The CLI uses the same explicitly selected original ceilings for this admission and separately
requires `--dwell-restore-max-frames`. Prefix replay must reproduce every recorded counter and
the complete canonical trace before the native owner can continue.

Native hot advancement is proportional to newly processed positions and preserves its forward
source cursor. **Cold resume replays the complete prefix**; repeated short-lived CLI processes
therefore pay growing prefix costs. Checkpoint publication also verifies the original source
and selected capsules through the existing publication guard. That verification may read the
whole recording. Metadata, capsule and publication I/O have their existing independent bounds;
the seven native counters are not a total-system I/O, memory, latency or energy measurement.

## Keep one native owner between scheduled slices

The reusable API is `fss_reference::ingest::long_dwell::incremental`:

1. `PreparedIncrementalDwell::new` validates a complete immutable request without decoding.
2. `prepared.start()` creates one native owner. It borrows the prepared request, and does not
   hold a deployment or source-file borrow between steps.
3. `running.advance(&deployment, maximum_frames, &cx)` processes only the next admitted slice.
   The caller can release the deployment lock and schedule other work between successful steps.
4. `running.retain(&mut deployment, &cx)` publishes an immutable checkpoint when desired.
5. Once `running.complete()` is true, `running.finish(&deployment, &cx)` returns the existing
   complete `LongDwellReport`; the original explicit event publication API applies.
6. To request a trained terminal stage, call
   `report.classify_with_detector(&deployment, &detector, &cx)` with an explicitly verified
   `LongDwellDetector`. The method replaces the report only after native classification,
   encoding and exact source/authority/privacy checks succeed. Refusal preserves the untrained
   report and its original scan reservation.

After a process restart, `RetainedDwellCheckpoint::open` validates exact pins, graph custody,
current source and original recipe without executing perception. `saved.resume` admits and
replays the prefix, compares its complete checkpoint bytes, rechecks custody, and returns a
native owner positioned at the next frame. `restoration_work()` exposes this extra work.

Each advance checks cancellation and the original deployment/site/principal, durable authority
head, source completion and privacy generation. A failed advance poisons that in-memory owner
because its native state may be partially advanced. Continue from the last durable checkpoint
under a new separately admitted owner. An interrupted checkpoint publish follows the existing
root-last exact-retry path; it cannot invent a completed event.

Checkpoints are distinct immutable roots and consume the deployment's existing spool, root and
ledger quotas. Callers can advance many hot slices between retained checkpoints. Retention
frequency and available root capacity must accommodate the requested schedule; there is no
automatic unbounded checkpoint history.

## Retained source and supported modes

The first version accepts completed **flat MJPEG imports** with explicit capture-time hints
and the existing supported `gray` or `ycbcr` interpretation. The loose original input can be
removed after import; the retained source chunks, selected capsules, import root and checkpoint
body/manifest must remain intact. Missing, deleted, stale or damaged custody refuses. A cached
native owner or cached metadata never repairs a missing published checkpoint body.

Partitioned imports are explicitly refused before native decoding. Their aggregate metadata
names typed part roots which are not graph children; the first checkpoint format deliberately
does not claim that retaining only the aggregate closes all part custody. H.264/H.265
checkpoint continuation, sensor-health screening, health retention and coverage retention
remain refused in incremental mode. Trained packages run only at the completed temporal
boundary described above. Calibrated fusion requires an already complete, exactly pinned
checkpoint and uses the separate read-only path; partial checkpoint advice is refused.
Existing whole-recording paths retain their supported codec, health and fusion capabilities.

The capture-time assumptions, masked-zone exclusions, actual-match rule, misses, excessive time
gaps and decode-refusal resets remain the existing dwell semantics. Scheduling boundaries add
no resets or final samples. Neither a checkpoint nor a completed sampled-dwell hypothesis proves
continuous occupancy, detection quality, absence or alert authority. Calibrated class advice
requires its own applicable, explicitly pinned profile.
This is bounded continuation over a completed recording; live camera acquisition, append-only
source growth and an automatic long-running scheduling daemon are separate capabilities.

## Format and executable regressions

The canonical checkpoint body domain is `fss.incremental_dwell_checkpoint.v1` (FMT-010), its
complete recipe domain is `fss.incremental-dwell.recipe.v1`, and its manifest kind is
`recorded-incremental-dwell-checkpoint-v1`. The source-closed graph uses the existing
`local_root_reachability` publication owner. No checkpoint authority family, mutable serialized
tracker format, new effect authority or changed whole-recording event encoding is introduced.

The native library regressions exercise multiple hot chunkings, cold prefix equality, one-shot
analysis/proposal/event identity, misses/gaps/refusals across boundaries, original allowance
exhaustion, independent restore admission, current privacy refusal, missing custody, forged
prefix rejection, cancellation, exact root retry and unsupported source modes. The real CLI
regressions execute the emitted continuation and event-publication commands in new processes,
with paths containing spaces, after the original source file is removed. They cover progress
export, changed-recipe refusal and one event after multiple steps and exact retries.

Terminal-classifier contracts compare complete native results with uninterrupted trained
analysis, exercise late cancellation and original-budget refusal, and preserve positive/empty
source, actor, privacy and health fences. Real CLI processes defer a missing package across
128/256-frame prefixes, finish at 300, publish/retry exactly once, and execute retained-model
replay after loose inputs disappear. Wrong-package and exhausted-budget attempts preserve the
completed temporal checkpoint; untrained approvals remain invalid for trained candidates.

Completed-checkpoint fusion regressions compare native results and advice with a one-shot
analysis at the same authority basis, verify unchanged checkpoint pins and journals, refuse
partial prefixes even when a step could finish them, and exercise empty inventories, stale
profile/source/recipe bindings, explicit restoration limits and guarded output. These synthetic
contracts do not qualify detector accuracy or field calibration.

```sh
cargo test -p fss-reference --lib ingest::long_dwell::tests::incremental
cargo test -p fss-reference --lib ingest::long_dwell::tests::classify
cargo test -p fss-cli --bin fss-event watch::incremental
cargo test -p fss-cli --test watch_stream_dwell_cli incremental
```
