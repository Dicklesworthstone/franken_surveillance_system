# Native replay of retained dwell events

This page documents the dedicated MJPEG `fss-replay-dwell` command. The generic
[`fss-event read` and `verify` commands](long_event_replay.md) also support retained sampled-dwell
events from native AVC and HEVC recordings, including trained classifier replay. Their second
selection pin is the episode provenance root; the dedicated command below keeps its existing
shared-analysis-root pin.

`fss-replay-dwell` recovers the original perception recipe from a committed whole-recording
MJPEG dwell event and can execute that recipe again from retained source. The original source
file and the original `fss-event watch` command are not required. Detector-enabled events also
retain their exact native model package, so no loose model file is needed. This connects the retained
trace to executable verification instead of treating consistent metadata hashes as proof that
perception actually produced the claimed result.

This is an implemented, unqualified deterministic-reference replay slice. It does not complete
FSS-083's general temporal verifier, the independent-verifier/quality gates, historical replay
of arbitrary event revisions, or production qualification.

## Inspect, then explicitly replay

Start with an event produced and published by `fss-event watch --stream-dwell`:

```sh
fss-replay-dwell inspect \
  --root /path/to/deployment --site site:home \
  --event-id "${EVENT_ID:?supply the committed long-dwell event ID}"
```

Inspection reads the current event through the existing authority reader, checks the committed
and visible episode/analysis roots, decodes the original bounded recipe, and checks its source
and current privacy bindings. It returns `inspected_not_replayed`, `native_replayed: false`,
and no decoded-frame count. It does not decompress source media or certify derived observations.
Opening uses the immutable retained source. It can run while capture holds the writer, and
does not acquire a publisher, recover a journal or change retained state.

The returned `verification_command` is a shell-quoted command with both exact selection pins and
all execution/report ceilings. Review and run that command, or invoke the verifier explicitly:

```sh
fss-replay-dwell verify \
  --root /path/to/deployment --site site:home \
  --event-id "$EVENT_ID" \
  --expected-event-revision "${EVENT_REVISION_DIGEST:?supply the inspected revision digest}" \
  --expected-analysis-root "${ANALYSIS_ROOT:?supply the inspected shared analysis root}" \
  --execute-perception yes
```

Both pins are required. An event identifier alone is not an execution selection, and a
publication approval is not a replay pin. A changed revision or analysis fails before perception.
The explicit acknowledgement permits potentially expensive native computation; it does not
prepare an effect, approve a different event, or grant any new standing capability.

Only current, original revision-1, unclassified/indeterminate whole-recording dwell events are
admitted. Short-watch/short-dwell events, previews, merely staged provenance and superseding
review revisions are not relabelled as supported. The source must remain a completed retained
MJPEG/JPEG import with its original operator capture hints. No H.264/HEVC or remote reconstruction
fallback is introduced. A changed sibling candidate revision can also trigger the producer's
existing conflict refusal; replay does not overwrite it to force a match.

## What native replay checks

The reader reconstructs the source import, exact segment range, image-coordinate zones,
foreground thresholds, tracker settings, duration/gap/count rule, decoder-refusal policy and
whether the conservative-v1 health screen was used. None of these can be overridden through the
replay command. Incompatible tags, extra records, malformed lengths, invalid counts, truncated
frames, non-finite geometry and inconsistent source bindings are refused.

The verifier then calls the actual `LongDwellReport` execution path. It reads and hashes source
chunks, decodes JPEG frames, applies the sensor's current mask, runs foreground detection,
Kalman/global-IoU tracking, sampled dwell and the original optional visual screen. For trained
events it also reconstructs qualifying-episode-only actual-sample selection and reruns the retained
native classifier with its exact package, threshold, kernel backend and budgets. It compares
the complete regenerated canonical analysis digest, the selected event's revision digest and its
current publication state, including every class record and typed budget/refusal outcome. A
successful result is `native_replay_matched`; the result type is
constructible only after those checks. A valid stored trace alone cannot produce that result.

The adversarial library regression rebuilds every hash and containing manifest after falsifying
one claimed decoded-luma digest, and publishes the resulting internally consistent claim through
normal reference publishers. Inspection can read that validly addressed metadata; actual source
replay must reject it as `dwell_native_replay_diverged`.

Matching proves deterministic reproduction from the retained source under this implementation.
It does not prove physical truth, correct tracking of one physical object, continuous occupancy
between frames, intent, a threat, sensor health, absence, or detector quality. Deterministic
implementation bugs can reproduce too. Original capture hints remain owner assumptions, and a
no-findings health screen is not a health certificate. No signature or independent ground truth
is inferred from matching content addresses.

## Privacy, authority and failure

The current mask must exactly match the original analysis binding. A newer privacy generation
refuses the old lineage before pixel execution; the verifier never loads an old mask as an
override or falls back to unmasked pixels. Missing/corrupt source, authoritative deletion,
retracted roots, an unverifiable authority head or unavailable provenance return refusal, not a
successful empty result. The command does not fetch, repair, re-import, resend or publish anything
to make a replay pass.

The library consumes an active, root-scoped `ReplayCx`. The local CLI assumes execution by the
authorized deployment owner, like the existing watch/replay commands; `--principal` is an audit
identity, not a remote credential. Another authorized reader can reproduce a result without
inheriting the publisher's approval.

Inspection and replay use one immutable retained source with an exact opening authority snapshot.
The complete report remains buffered until the opening metadata, selected payloads, custody,
publication records and both journal roots have passed final revalidation under the same read
allowance. A writer may remain open throughout a successful read; an authority advance during
the request refuses completion and requires a fresh request. This is not an uninterrupted
historical-snapshot service across new capture commits.

Neither operation stages, publishes, repairs or transitions an effect. They do not persist a
verification receipt, change the event to corroborated, release a hold, or authorize an alert.
Torn histories are refused without truncation or recovery. The returned anchor identifies the
exact consumed snapshot.

## Budgets and output

The original semantic recipe is immutable, but sufficient current safety ceilings may be selected
for this replay. A trained event retains all original native scan and package ceilings; replay
requires them to fit the current bounds and then executes those exact retained limits. It never
substitutes a smaller inference allowance, new threshold or another backend to force a match.
Insufficient work returns a refusal instead of a partial verification.

| Option | Default | Scope |
|---|---:|---|
| `--max-metadata-bytes` | 16 MiB | Aggregate selected provenance payloads, including the optional retained model; hard maximum 64 MiB |
| `--max-read-bytes` | 1 GiB | One cumulative payload allowance for opening metadata, native reads and all final rereads; hard maximum 4 GiB |
| `--max-read-objects` | 1,000,000 | One cumulative payload-read-attempt allowance, including opening metadata and final checks; hard maximum 4,000,000 |
| `--source-read-bytes` | 512 MiB | Actual verified source-chunk bytes fetched by native replay |
| `--pixel-budget` | 1,073,741,824 | Temporal luma samples plus optional classifier-pass pixels; health screening has its own counter under the same ceiling |
| `--assignment-work` | 1,073,741,824 | Whole-scan checked tracker admission bound |
| `--trace-bytes` | 8 MiB | Complete regenerated length-framed metadata trace |
| `--decode-work` | 100,000,000 | Whole-scan native JPEG work allowance |
| `--max-report-bytes` | 65,536 | Complete JSON plus its final newline; hard maximum 1 MiB |

`--max-dimension`, `--max-pixels` and `--max-segment-bytes` also narrow native per-frame/read
ceilings. These execution options are refused on `inspect`, which runs no perception; metadata
and report bounds apply to both commands. Arguments are bounded, duplicates and unknown options
are refused, and an absent deployment is rejected without creating a context directory. The
native immutable reader applies its bounded layout, journal and snapshot contracts; every
content read is charged to the same aggregate allowance. The generated verification command
preserves both aggregate ceilings in addition to the native execution limits.

Selected provenance traversal has at most 273 payload reads (the base graph, exact event witness,
and up to 32 episodes
with 8 class records each), fixed manifest shapes and
per-object allocation bounds applied by the sealed retained-source owner. The original
65,536-position, 64-track, 32-episode and trace ceilings remain in force. Metadata parsing and
native stages poll cancellation; the health screen polls every row. The CLI additionally applies
a cooperative 60-second deadline at read admissions and final delivery. Blocking filesystem
operations and compute kernels do not have a hard-real-time preemption guarantee.

The report names the retained detector package digest when present and distinguishes actual
replay frame/source-read counts from configured ceilings.
Selected metadata counts include the canonical event and its lineage rereads, but exclude
deployment opening and native source reads. The separate aggregate allowance covers all of them
plus final revalidation; neither counter is total-system I/O, RAM, energy or latency. An error
produces no JSON prefix, and an oversized complete report is refused. The CLI writes only stdout
and stderr, never an output file or raw pixel buffer. For non-UTF-8 deployment paths the command
hint is null rather than lossy; repeat the original OS-byte path with the returned pins.

## Compatibility and validation

Existing model-free producer bytes, digest domains, event schema, screening policy, dependencies
and publication semantics are preserved. The decoder owns the v1 long-dwell wire profile,
its health extension and the optional classifier selection/recipe/outcome suffix; unknown
incompatible profiles are refused. The local JSON is an operation result, not a durable authority
format. Native qualification remains separate from deterministic replay.

```sh
cargo test -p fss-reference --lib long_dwell_replay
cargo test -p fss-reference --test long_dwell_immutable_contract
cargo test -p fss-reference --lib long_dwell::tests::detector
cargo test -p fss-cli --test replay_dwell_cli
cargo test -p fss-cli --test watch_stream_dwell_cli
```

Library regressions cover real imports, cold 300-frame replay, screened replay, exact
pins, preview refusal, privacy invalidation, cumulative limits, cancellation, missing source,
malformed encodings, internally consistent forged derivation and an independent authorized reader.
Actual-process regressions cover both CLI modes, cold source-only operation, mandatory
acknowledgement/pins, refusal of overrides, malformed/missing deployments, budgets and privacy.
Immutable-reader contracts additionally cover writer-held native parity, exact cumulative
allowances and one-less refusal, late source/event/publication damage, privacy and effect-history
changes, wrong-root authority and cancellation. Process tests exercise both operations with the
writer held and prove torn effect history is not repaired or emitted as a partial success.

Trained native regressions additionally remove the loose source/model files before replay,
require retained package and class custody, and preserve exact inference exhaustion across
episode boundaries. These synthetic recordings test reproducibility and refusal behavior;
they do not establish accuracy, performance or production qualification. Existing
source/dependency/toolchain and release gates are unchanged.
