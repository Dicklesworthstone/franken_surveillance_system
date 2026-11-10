# Query recorder-reported UTC in retained replay originals

`fss-archive query-replay-utc` finds native AVC or HEVC samples whose original
ONVIF replay RTP timestamps overlap an explicit UTC interval. It cold-loads an
independently pinned replay receipt, replays every original through its native
codec verifier and returns source citations. The recorder is not contacted.

This advances VIT-022 (`fss-vit022-recorder-retrieval-5js5o`). It adds historical
timestamp lookup to the [retained replay path](RTSP_RECORDER_REPLAY.md), including
[protected ONVIF recording selection](ONVIF_RECORDING_DISCOVERY.md). It does not
establish calibrated capture time, continuous recording or complete retrieval.

## Run an exact cold query

Retain the receipt root, request identity and complete source/catalog scope from
the approved capture preview and `replay_receipt_published` event. Supply those
independent pins, the actual codec and an explicit NTP era:

```sh
fss-archive query-replay-utc \
  --root /private/replay-archive --codec hevc \
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

The digest labels and source identifiers are placeholders. The example query is
the half-open interval `[2026-11-05T01:02:00Z, 2026-11-05T01:02:10Z)`. Replace all
pins and coordinates with the intended retained source and external era basis.
An era is never selected from the requested range, acknowledged range, receive
clock, host wall clock, RTP timestamp or RTCP sender report. Use `--codec avc` for
an AVC receipt; stored metadata cannot choose a verifier or enable fallback.

The existing archive owner takes exclusive locks and may perform its normal
recovery I/O when opened. The query creates no new publication, import, deletion
or network operation. It emits one complete bounded JSON report, with no original
media payload. Invalid options are rejected before archive opening; absent,
changed, corrupt or tombstoned required originals refuse the whole query.

## Interpret the result

The schema is `fss.local_replay_time_operator_report.v1`. It separates:

- `matches`: native samples with usable recorder assertions conservatively
  overlapping the query.
- `unknown`: native samples whose UTC cannot be established from the supported
  replay assertion, regardless of the requested interval.
- `source_only`: all trailing HEVC source groups, including boundary lookahead.
  Their timestamps never create media samples or positive sample matches.
- `known_samples_outside_query`: the count of known native samples outside the
  selection. Their evidence still contributes to `index_digest`.

Each sample keeps its native ordinal, decode ticks, presentation ticks, duration
and RTP timestamp. B-frame presentation and recorder UTC can differ from decode
or arrival order. No monotonic recorder-time requirement is invented. Exact
extended sequence endpoints, distinct packet count, `packet_set_digest` and
`proof_digest` cite the original association. `windows[].original_leaf_digests`
lists source, initialization, media and index hashes in that order.

The first contributing packet of the complete native access unit must carry the
fixed ONVIF `0xABAC` extension. AVC parameter sets relocated into initialization
and HEVC in-band prefixes remain part of that source association. Later packets
may omit the extension; a later valid assertion cannot repair a missing or
foreign first extension. Repeated semantic assertions must agree. Malformed
extensions, timestamp disagreement or ambiguous packet ownership remain explicit
unknown reasons. Padding stays in the original packet but has no time semantics.

`recorder_utc_ns.earliest` and `.latest` are the floor and ceiling of the exact NTP
fraction, expressed as decimal-string Unix nanoseconds. These bounds account for
numeric rounding only; recorder clock error remains unknown. Selection uses
`latest >= query_start && earliest < query_end`, so a one-nanosecond rounding
enclosure can conservatively intersect a boundary. Supported UTC is 1970–9999;
raw-zero NTP remains unknown. An assertion outside the requested or acknowledged
PLAY range remains observable, including possible clean-point preroll; the query
does not clip it or substitute either range for its timestamp.

The C/E/D/T flags are retained device assertions. They do not close an unfinished
picture or establish continuity, EOF, terminal retrieval or coverage. The CSeq
check compares only eight bits; `play_cseq_correlation` remains `low_byte_only`
even when it agrees with the independently retained successful PLAY CSeq.

`index_digest` binds the independent receipt/request/scope/codec pins, explicit
era and every observed association. It is independent of query interval and
limits. `report_digest` additionally binds the query, limits, accounting and exact
result partition. The original receipt preserves approval and any protected
ONVIF discovery provenance. Neither digest grants source access or timestamp
authenticity. Empty results do not prove absence or complete interval coverage.

## Bounds and refusal

| Option | Default | Admitted range |
|---|---:|---:|
| `--max-query-windows` | 64 | 1–64 |
| `--max-query-samples` | 16,384 | 1–16,384 |
| `--max-query-packets` | 262,144 | 1–262,144 |
| `--max-query-source-bytes` | 268,435,456 | 1–2,147,483,648 |
| `--max-query-results` | 4,096 | 1–32,768 |

Before original reads, each window reserves the native 32 MiB verification
ceiling. The default 256 MiB allowance therefore admits eight windows even when
their actual objects are small. `source_bytes_reserved` reports that conservative
reservation; `verified_source_bytes` reports the actual original root plus four
child payloads verified. Receipt metadata, spool envelopes and normal archive
opening are outside that original-payload accounting and retain their own bounds.
Every original child read is capped by the remaining window allowance before
allocation, including a hostile replacement of a later child.

Sample and packet limits check receipt admission and actual projected counts.
They do not lower the native verifier's intrinsic per-window ceiling of 256
samples and 4,096 packets. A forged smaller descriptor can consume that bounded
verification before its disagreement refuses the query. No successful projection
exceeds the supplied limits.

The result limit counts `matches + unknown + source_only` together. The CLI also
requires the complete report to fit 8 MiB. There is no truncation or partial
success on a budget, allocation, custody, cancellation or output-size refusal.
The existing `--timeout-ms`, `--max-scan-roots`, `--max-objects`,
`--max-object-bytes` and `--max-total-bytes` limits remain independent. Cancellation
is cooperative; exact roots, tombstones and companion bytes are checked again
after native projection and before a complete result is released.

Native whole-query error codes are `ERR-REPLAY-TIME-SCOPE-001`,
`ERR-REPLAY-TIME-INTERVAL-001`, `ERR-REPLAY-TIME-LIMIT-001`,
`ERR-REPLAY-TIME-CUSTODY-001` and `ERR-REPLAY-TIME-CANCELLED-001`. Argument/open/output
failures retain existing CLI codes. Header-level problems remain row-level unknowns
with the packet parser's stable code where applicable; they are not empty success.

## Library and validation

The library entry point is
`fss_reference::rtsp::recording_replay::time::query_replay_time`, taking an existing
`LocalRootPublisher`, a `ReplayTimeQuery` and `PublishCancellation`. It reuses the
native receipt loader with metadata admission before original reads and sealed
native callbacks after source verification. Existing recording, catalog, live
capture and direct replay receipt encodings are unchanged. `query-utc` retains
its existing node-clock meaning.

There are 44 new contracts: 18 packet contracts in `onvif_replay_contract`, 18
reference contracts under `recording_replay_contract::utc`, and eight real CLI
process contracts under `archive_replay_process::time`. They cover first-packet
ownership, real fragmented/aggregated source maps, source-only tails, reordered
presentation, era/fraction boundaries, weak CSeq correlation, cold pins,
tombstones, cancellation, aggregate limits and an instrumented hostile late-child
read bound.

On pinned nightly `2026-08-31`, **36 parser contracts passed**: all 18 new packet
contracts and the 18 shared production ONVIF wire contracts (14 recorder-wire and
four existing snapshot-wire cases), with zero executed-test failures or ignored
cases. The 18 new reference and eight new CLI query contracts remain **unexecuted**.
Four full-build or metadata-check attempts were terminated by SIGKILL in unchanged
Asupersync 0.5.0 before the new reference or CLI feature source compiled.
Independent source/API review and scoped pinned formatting are complete. The
[retained native results](validation/2026-11-10-recorder-time-native-results.json)
identify the exact sources, commands, passes and blocked attempts. Parser passes
do not establish that the cold-query source/custody/operator path passed. Hardware recorder
interoperability, replay-provenance-preserving ordinary import, calibrated device
time and release qualification remain open. VIT-022 is not closed.

Protocol interpretation follows the [ONVIF Streaming Specification](https://www.onvif.org/specs/stream/ONVIF-Streaming-Spec.pdf),
sections 6.3, 6.3.1, 6.5.4 and 6.11, and [RFC 5905 section 6](https://www.rfc-editor.org/rfc/rfc5905#section-6).
