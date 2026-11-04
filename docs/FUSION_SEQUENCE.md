# Continue source-once fusion across CLI invocations

`fss-fuse --sequence` accumulates ordered fusion observations, writes a complete binary
checkpoint, and resumes from an independently retained checkpoint digest. A declared
source contributes its signed likelihood at most once for the lifetime of the sequence,
including after a restart, an alias change, or a numerical regime reset.

This is an offline computation over caller-supplied observations. It writes only the new
checkpoint requested by `--checkpoint-out` and returns a JSON report. It does not ingest
camera data, activate a policy, publish an event, or send a notification.

## Run the two-camera example

From the repository root, build the binary and create a fresh output directory:

```sh
cargo build -p fss-cli --bin fss-fuse --locked
fusion_demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/fss-fusion-sequence.XXXXXX")"

target/debug/fss-fuse \
  --sequence fixtures/fusion_sequence/first.json \
  --checkpoint-out "$fusion_demo_dir/first.checkpoint" \
  > "$fusion_demo_dir/first-report.json"
```

Only after that command succeeds, obtain the pin from its report and pass it explicitly
to the next invocation:

```sh
fusion_checkpoint_digest="$(python3 -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["checkpoint_digest"])' \
  "$fusion_demo_dir/first-report.json")"

target/debug/fss-fuse \
  --sequence fixtures/fusion_sequence/next.json \
  --checkpoint-in "$fusion_demo_dir/first.checkpoint" \
  --checkpoint-digest "$fusion_checkpoint_digest" \
  --checkpoint-out "$fusion_demo_dir/next.checkpoint" \
  > "$fusion_demo_dir/next-report.json"

python3 - "$fusion_demo_dir/next-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
print("sources:", report["sources_seen"])
print("accumulated millibans:", report["accumulated_millibans"])
for step in report["steps"]:
    dispositions = [row["disposition"] for row in step["source_receipt"]["admissions"]]
    print(step["step_index"], step["step_delta_millibans"], dispositions,
          "crossed threshold:", step["crossed_alert_threshold"])
PY
```

The fixtures use illustrative direct likelihood intervals of `[600, 600]` millibans,
distinct declared camera domains, and a sequence threshold of 1,000 with two supporting
domain clusters. The continuation has these results:

| Observation | Global step | Disposition | Added millibans | Accumulated millibans | Sources consumed |
|---|---|---|---|---|---|
| East camera in `first.json` | 1 | `admitted` | `[600, 600]` | `[600, 600]` | 1 |
| Same east source under `east-retry` in `next.json` | 2 | `already_admitted` | `[0, 0]` | `[600, 600]` | 1 |
| New west source in `next.json` | 3 | `admitted` | `[600, 600]` | `[1200, 1200]` | 2 |

The final `crossed_alert_threshold` is `true`. It reports the accumulator's numerical
condition; `effect_authority` remains `false`. Each `effective_fusion` object instead
describes that step's incremental query and its own prior and decision policy. Its
decision need not equal the accumulated sequence's threshold result.

The example source hashes identify fixed demonstration declarations. They are not
camera custody proofs or measured calibration. For real continuation, retain the
successful report's checkpoint digest in storage you trust independently of the checkpoint
bytes, and retain which digest is the latest accepted head. Recomputing a digest from an
untrusted checkpoint and using that same value as the expected pin provides no independent
substitution check.

## Request and source identity

Every request contains exactly these top-level fields:

```json
{
  "schema": "fss.fusion_sequence.v1",
  "hypothesis": "event:entry",
  "config": {
    "alert_threshold_mban": 1000,
    "floor_mban": -10000,
    "ceiling_mban": 10000,
    "min_independent_clusters": 2
  },
  "source_limit": 4,
  "steps": []
}
```

An empty step list is allowed: it publishes a genesis checkpoint, or an unchanged resumed
checkpoint at a new path. The hypothesis, all four configuration values, and source limit
must match the restored state exactly. A mismatch refuses continuation instead of starting
a new accumulator. Observation `now_ns` values must never decrease, including across resets
and restarts; an equal-time retry is allowed. Integer inputs may use JSON integer tokens
or exact decimal strings. Fractional and exponent number tokens are refused.

An observation step is `{"kind":"observe","query":QUERY,"sources":BINDINGS}`. `QUERY`
uses the existing `fss.fusion_query.v1` or `fss.fusion_query.v2` input accepted by
`fss-fuse --query`; the two fixtures show complete direct-LLR examples. `BINDINGS` maps
**every original evidence ID** to a canonical `sha256:` or `blake3:` digest, or to explicit
`null` for a nonnumeric row. Missing and extra bindings refuse. A calibrated, observed
row always needs a source digest.

Keep the digest stable when retrying the same source under another evidence alias. A
different source digest declares a different source; the CLI cannot establish whether
two declarations describe the same physical observation. Reusing a consumed digest with
changed sensor, event kind, failure domains, calibrated interval or generation, or
observability refuses the entire invocation. Raw-score observations additionally retain
the exact score and calibration artifact identity, so changing a score within the same
calibration bin also refuses. The alias itself may change.

Negative and zero-valued calibrated observations consume source capacity too. Nonnumeric
missing, stale, redacted, or uncalibrated rows contribute no likelihood and reserve no
lifetime source slot. A missing row can therefore use `null`; a later actual calibrated
observation can supply its source identity. Existing missing rows remain visible in the
effective query, so replay filtering does not manufacture complete observation or absence.

For raw scores, pass the calibration artifacts with repeated `--calibration FILE`
options, up to sixteen distinct artifacts. Each score names its exact `generation` and
`digest`; the artifacts are reconstructed and digest-checked by the existing calibration
loader. Changing the representation of an already admitted source from direct LLR to raw
score is also a source conflict. See [fusion calibration](FUSION_CALIBRATION.md) for
artifact generation and the limitations of caller-declared score spaces.

## Reset a numerical regime

The three accepted reset forms are:

```json
{"kind":"reset","reason":{"kind":"operator_reset","reason":"operator reviewed the new regime"}}
{"kind":"reset","reason":{"kind":"sensor_health_degraded","sensor":"camera:east","reason":"image obstructed"}}
{"kind":"reset","reason":{"kind":"clock_continuity_broken","sensor":"camera:east","gap_ns":"1000000000"}}
```

These are separate example steps, not one JSON document. Sensor and reason text must be
nonempty, contain no control characters, and fit within 256 UTF-8 bytes. A reset clears
active numerical evidence and supporting domains. It retains the lifetime source inventory,
raw-input commitments, last observation time, and transcript ancestry. Replaying an old
source after a reset therefore still contributes zero. A reset does not replenish capacity.

## Bounds and publication behavior

| Resource | Limit |
|---|---|
| Ordered steps in one invocation | 64, including observations and resets |
| Distinct consumed sources over all invocations and regimes | Configured `source_limit`, from 1 through 4,096 |
| Evidence rows in one ordinary query | 256 |
| Input JSON document or one calibration artifact | 1 MiB |
| JSON parser | Depth 32; 65,536 nodes; 64 KiB per string, with tighter native field limits |
| Complete CLI checkpoint | 16 MiB |
| Complete JSON report | 16 MiB |

The byte caps can be reached **before** the declared source capacity, especially with large
failure-domain inventories or large per-step reports. Reduce a report's batch size when
appropriate; splitting a batch does not shrink the lifetime checkpoint inventory. The CLI's
16 MiB envelope limit is separate from the core library checkpoint's 32 MiB bound.

`--sequence -` reads stdin. At most one sequence or calibration input can use stdin.
Checkpoints require regular files and a named new output path. Sequence, configuration,
step and reset objects reject unknown fields. Embedded ordinary query objects retain their
existing parser behavior, including ignored additional fields. Duplicate JSON object keys
are always refused.

The complete invocation executes and its complete checkpoint and report sizes are checked
before publication. If a later step has a conflict, invalid binding, exhausted capacity,
backwards time, or other input error, no successful prefix is published and no new
checkpoint is created. Retry from the prior accepted checkpoint after correcting the
request. Existing output files are never replaced, even when their contents would match.

On successful publication, the file contents are synchronized; on Unix its parent directory
is synchronized too. A filesystem or synchronization failure can leave a new partial or
unconfirmed file, so inspect and verify that file before choosing how to retry. An output
stream failure can also occur after the checkpoint has been written. These cases do not
replace the previous checkpoint and do not make a missing success report an accepted head.

## Reading and verifying the report

The request schema is [fusion_sequence.v1.json](../schemas/fusion_sequence.v1.json); the
report schema is [fusion_sequence_report.v1.json](../schemas/fusion_sequence_report.v1.json).
The report includes:

- Initial and final step indexes, final numerical interval, and lifetime source count.
- Each source admission or replay disposition, the embedded numerical transcript, and
  the effective fusion decision. Reset steps have `null` input bindings and decisions.
- `source_inventory_digest` for the core's complete consumed-source inventory and
  `raw_source_inventory_digest` for the adapter's additional raw-input commitments.
- `sequence_transcript_digest` for the ordered CLI history, including exact submitted
  calibration bindings and preserved observation times.
- The supplied `previous_checkpoint_digest`, the new `checkpoint_digest`, and its byte size.

Splitting the same ordered transitions across successful invocations preserves the final
checkpoint bytes and transcript heads. The JSON reports themselves differ because they
describe different batches and predecessor checkpoints. The CLI checkpoint is a binary
wrapper that also preserves raw inputs and observation time; use it with this CLI's resume
options, rather than interchanging it with the bare
[core checkpoint](FUSION_CHECKPOINT.md).

Schema validation checks structure. It does not verify digest contents, reconstruct
transcripts, compare configuration across files, or prove source authenticity. Native
restore validates the expected SHA-256, format, complete inventories and numerical state.
Digest pinning does not authenticate who supplied a checkpoint, establish freshness, or
prevent selecting an older valid checkpoint. The caller owns the latest accepted head.
Declared source identities and domains do not establish physical uniqueness, independent
errors, field calibration quality, anytime-valid false-alarm rates, or effect authority.

For the complete option summary, run `fss-fuse --sequence-help`.
