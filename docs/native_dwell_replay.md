# Native replay of retained dwell events

`fss-replay-dwell` recovers the original perception recipe from a committed whole-recording
MJPEG dwell event and can execute that recipe again from retained source. The original source
file and the original `fss-event watch` command are not required. This connects the retained
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
Deployment opening can still perform its existing custody verification and restart recovery.

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
Kalman/global-IoU tracking, sampled dwell and the original optional visual screen. It compares
the complete regenerated canonical analysis digest, the selected event's revision digest and its
current publication state. A successful result is `native_replay_matched`; the result type is
constructible only after those checks. A valid stored trace alone cannot produce that result.

The adversarial library regression rebuilds every hash and containing manifest after falsifying
one claimed decoded-luma digest, and publishes the resulting internally consistent claim through
normal reference publishers. Inspection can read that validly addressed metadata; actual source
replay must reject it as `dwell_native_replay_diverged`. This regression has been added but has
not yet been executed in the authoring environment.

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

The existing deployment open takes exclusive locks and may reconcile interrupted operations or
sync custody. It is not advertised as universally mutation-free. Inspection and replay themselves
have no staging, publication, repair or effect-transition call. They do not persist a verification
receipt, change the event to corroborated, release a hold, or authorize an alert. The returned
anchor records the consumed snapshot; an authority change during the request refuses completion.

## Budgets and output

The original semantic recipe is immutable, but sufficient resource ceilings may be selected for
this replay. Raising a ceiling never changes the expected analysis or event; insufficient work
returns a refusal instead of a partial verification.

| Option | Default | Scope |
|---|---:|---|
| `--max-metadata-bytes` | 16 MiB | Aggregate selected provenance payloads read by this adapter; hard maximum 32 MiB |
| `--source-read-bytes` | 512 MiB | Actual verified source-chunk bytes fetched by native replay |
| `--pixel-budget` | 1,073,741,824 | Whole-scan foreground luma samples; the optional health screen has its own counter under the same ceiling |
| `--assignment-work` | 1,073,741,824 | Whole-scan checked tracker admission bound |
| `--trace-bytes` | 8 MiB | Complete regenerated length-framed metadata trace |
| `--decode-work` | 100,000,000 | Whole-scan native JPEG work allowance |
| `--max-report-bytes` | 65,536 | Complete JSON plus its final newline; hard maximum 1 MiB |

`--max-dimension`, `--max-pixels` and `--max-segment-bytes` also narrow native per-frame/read
ceilings. These execution options are refused on `inspect`, which runs no perception; metadata
and report bounds apply to both commands. Arguments are bounded, duplicates and unknown options
are refused, and an absent deployment is rejected before creating a context directory. Existing
regular journals of at most 64 MiB each are required by this CLI's startup preflight.

Selected provenance traversal has at most sixteen payload reads, fixed manifest shapes and
per-object allocation bounds applied by the existing read-only spool owner. The original
65,536-position, 64-track, 32-episode and trace ceilings remain in force. Metadata parsing and
native stages poll cancellation; the health screen polls every row. No deadline or hard-real-time
preemption is claimed for filesystem operations or compute kernels.

The report distinguishes actual replay frame/source-read counts from configured ceilings.
Metadata counts exclude the existing deployment-open/current-event reader and native source
reader's own costs; these are not total-system I/O, RAM, energy or latency measurements. An error
produces no JSON prefix, and an oversized complete report is refused. The CLI writes only stdout
and stderr, never an output file or raw pixel buffer. For non-UTF-8 deployment paths the command
hint is null rather than lossy; repeat the original OS-byte path with the returned pins.

## Compatibility and validation

No existing producer encoding, digest domain, event schema, screening policy, dependency or
publication behavior is changed. The decoder owns the existing v1 long-dwell wire profile and
its explicit health extension; unknown incompatible profiles are refused. The local JSON is an
operation result, not a new durable authority format. The inherited long-dwell central-format
registration and native qualification work remain pending.

```sh
cargo test -p fss-reference --lib long_dwell_replay
cargo test -p fss-cli --test replay_dwell_cli
```

Eleven library regressions cover real imports, cold 300-frame replay, screened replay, exact
pins, preview refusal, privacy invalidation, cumulative limits, cancellation, missing source,
malformed encodings, internally consistent forged derivation and an independent authorized reader.
Six actual-process regressions cover both CLI modes, cold source-only operation, mandatory
acknowledgement/pins, refusal of overrides, malformed/missing deployments, budgets and privacy.

Rust compilation, these Rust tests and rustfmt have not run in the authoring environment, which
lacks the Rust toolchain. No native passing result, performance or production qualification is
claimed. Existing source/dependency/toolchain and release gates are unchanged.
