# Query recorder UTC from an imported replay

`fss-file query-replay-utc` searches recorder-reported timestamps using a completed
[whole-receipt replay import](RTSP_REPLAY_IMPORT.md). It reads the replay companion
and every native AVC/HEVC original from the destination deployment, so the source
archive can be offline. It uses the same packet associations, UTC interpretation
and native proof domains as
[`fss-archive query-replay-utc`](RECORDER_TIMESTAMP_QUERY.md).

This is a historical source query. Recorder UTC remains a device assertion;
capture-time classification, clock calibration, retrieval completeness and
coverage are unchanged.

## Supply the exact retained source

Keep the `import_identity` from the approved replay import and the independently
retained receipt/request/source pins from capture and import planning:

```sh
fss-file query-replay-utc \
  --root /srv/fss/analysis --site site:home \
  --import-id sha256:RETAINED_IMPORT_IDENTITY \
  --codec hevc \
  --sensor sensor:front-door --stream stream:recorder-channel1 --generation 1 \
  --anchor sha256:OWNER_AUTHORITY_DIGEST \
  --receive-clock sha256:THIS_CAPTURE_RECEIVE_CLOCK_DIGEST \
  --decode-clock sha256:REPLAY_BOUND_DECODE_CLOCK_DIGEST --time-scale 90000 \
  --expected-replay-root sha256:RETAINED_RECEIPT_ROOT \
  --expected-replay-request sha256:RETAINED_REQUEST_IDENTITY \
  --ntp-era 0 \
  --utc-start-ns 1793840520000000000 \
  --utc-end-ns 1793840530000000000
```

Replace the digest labels and source identifiers with actual pins. The example
selects `[2026-11-05T01:02:00Z, 2026-11-05T01:02:10Z)`; the explicit NTP era needs
an external basis. Use `--codec avc` for AVC. The decode clock is the replay-bound
clock, not the original base clock. Neither the import nor stored metadata supplies
a missing codec, scope, receipt pin or era.

`--root` is an existing absolute **deployment** path and `--site` must match its
lineage. The command refuses a missing store instead of creating one. It requires
a completed `ADP-RTSP-REPLAY-ARCHIVE-001` import; an ordinary recording-window or
file import does not acquire replay provenance through this command.

No source archive path is needed. Native slot names retained in the report are
historical citations: the query resolves exact retained objects and current
import authority without requiring those slots in the destination. It creates
no temporary archive or substitute publication.

## Read the complete result

The outer JSON schema is `fss.retained_replay_time_operator_report.v1`:

| Field | Meaning |
|---|---|
| `schema` | The retained-query wrapper above. |
| `command` | `query-replay-utc`. |
| `import_identity`, `import_root` | The current completed retained import that supplied the originals. |
| `source_archive_required` | `false`. |
| `network` | `none`. |
| `report` | The complete existing `fss.local_replay_time_operator_report.v1` projection. |

For the same original bytes, independent pins, era, interval and query limits,
`report` has the same native query/index/report identities and rows as the archive
command. The wrapper adds destination custody context without changing those
canonical domains. The shared renderer also preserves the inner JSON projection.

Inside `report`, `matches` contains usable recorder assertions overlapping the
half-open query. `unknown` retains samples with missing, malformed, conflicting or
otherwise unusable assertions. `source_only` preserves trailing HEVC groups as
source evidence; it never adds media samples. Known samples outside the interval
remain in the complete index and its accounting.

Requested/acknowledged PLAY ranges, partial termination and protected ONVIF
selection pins remain visible. Full packet hashes bind the original header bytes;
CSeq correlation still checks only its low byte. UTC bounds enclose numeric NTP
rounding, not physical recorder clock error. Empty matches cannot establish absence.
See [the shared result interpretation](RECORDER_TIMESTAMP_QUERY.md#interpret-the-result)
for packet ownership, timestamp conflict and interval details.

## Bounds and refusal

| Option | Default | Maximum |
|---|---:|---:|
| `--max-query-windows` | 64 | 64 |
| `--max-query-samples` | 16,384 | 16,384 |
| `--max-query-packets` | 262,144 | 262,144 |
| `--max-query-source-bytes` | 268,435,456 | 2,147,483,648 |
| `--max-query-results` | 4,096 | 32,768 |
| `--max-source-bytes` | 67,108,864 | 67,108,864 |
| `--chunk-bytes` | 16,777,216 | 67,108,864 |
| `--max-segment-bytes` | 16,777,216 | 67,108,864 |
| `--timeout-ms` | 30,000 | 600,000 |

Every listed bound must be positive. Query admission reserves **32 MiB per native
window before original payload reads**. The default 256 MiB source allowance
therefore admits eight windows, even when their actual objects are small. The
complete receipt is scanned; narrowing the UTC interval does not skip windows
or refill a budget. Result limits count matches, unknowns and source-only groups
together.

The native proof has a separate 4 MiB read ceiling. Each companion readback is
bounded by the existing 64 KiB receipt ceiling. `source_bytes_reserved` and
`verified_source_bytes` in the inner report keep their archive-query meanings:
conservative native-window reservation and actual verified original closure
payload, respectively. Companion/proof authority reads remain separately bounded.

The retained-media options admit the imported movie's declared source/chunk
layout. They do not replace the native original-source allowance. The query
reconstructs source packet and sample mappings without decoding pixels or
emitting media bytes.

`--principal` defaults to `principal:local-operator`. Opening an existing
deployment holds its normal exclusive lock and may recover journals. Query
processing publishes no evidence, import, export or deletion. Current completion,
origin proof, native objects, companion bytes and deletion state are checked;
companion and import authority are rechecked before the report is released.
Damaged or deleted custody refuses instead of being repaired from another store.

Cancellation and deadline checks are cooperative at read, projection and rendering
boundaries. The complete outer JSON must fit **8 MiB**, including its nested
report. A custody, budget, cancellation or size refusal returns no successful
partial report. Native errors retain the existing
`ERR-REPLAY-TIME-SCOPE-001`, `ERR-REPLAY-TIME-INTERVAL-001`,
`ERR-REPLAY-TIME-LIMIT-001`, `ERR-REPLAY-TIME-CUSTODY-001` and
`ERR-REPLAY-TIME-CANCELLED-001` identities; option/open/output failures use the
CLI's existing error identities.

## Library and qualification

The entry point is
`fss_reference::ingest::rtsp_import::replay::query_retained_replay_time`.
It takes the deployment, import identity, complete `ReplayTimeQuery`,
`RetainedReadLimits`, `ReplayCx` and `PublishCancellation`, returning the same
`ReplayTimeReport` as the archive query. Codec-owned verification reconstructs
sealed originals before the shared packet-time projector visits them.

Focused targets are:

```sh
cargo test --locked --offline -p fss-reference --test rtsp_retained_replay_time_contract
cargo test --locked --offline -p fss-cli --bin fss-file replay_time::
cargo test --locked --offline -p fss-cli --test rtsp_replay_import_cli retained_time::
```

Six reference contracts cover real timestamped AVC/HEVC sources, ONVIF pins,
source-only lookahead, missing/malformed assertions, era/interval parity, offline
custody, limits, cancellation, corruption and committed deletion. Two command
parser cases and three real process cases cover the operator path. The existing
recording lifecycle script includes the native and process targets.

At the implementation checkpoint, source/API review, scoped formatting and
whitespace checks are complete; these added native cases have not been executed.
See [implementation status](../IMPLEMENTATION_STATUS.md) for the recorded
validation scope. This work advances VIT-022 without qualifying physical recorders,
calibrating device time or proving complete historical retrieval.

