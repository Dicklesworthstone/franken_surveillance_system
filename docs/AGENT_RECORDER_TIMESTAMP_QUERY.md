# Recorder UTC assertions in canonical agent queries

The existing AOP-005 `query` operation can verify a pinned recorder replay and
return its packet-linked UTC assertions through `fss query --target recordings`
and MCP `query`. It returns the ordinary `AgentResponseEnvelope` and cognitive
envelope, including current deployment obligations, uncertainty, evidence
handles, read accounting and protected context. The CLI and MCP use the same
parser, native query and renderer.

This mode reads original packet payloads internally to verify the assertions.
The operator must grant that source verification separately. The result contains
no media bytes and grants no export, device, publication or deletion authority.

Completed native replay imports also support this canonical query without an
archive directory: select `--retained-import` and preserve all independent
original recorder pins. The destination reader shares one immutable payload
budget through final revalidation. See the [retained-import CLI/MCP contract](AGENT_RETAINED_RECORDER_QUERY.md)
for its source grant, launcher and payload-read accounting.

## CLI

Supply independent pins from the replay capture/inspection and the source's
recording scope. Both roots must be existing absolute paths. Values below are
shell variables for those exact operator-selected identities, not discovered
defaults:

```bash
fss query --json --target recordings \
  --root "$DEPLOYMENT" --archive-root "$ARCHIVE" \
  --principal "$PRINCIPAL" \
  --codec hevc --sensor "$SENSOR" --stream "$STREAM" \
  --generation "$GENERATION" --source-anchor "$SOURCE_ANCHOR" \
  --receive-clock "$RECEIVE_CLOCK" --decode-clock "$DECODE_CLOCK" \
  --time-scale "$TIME_SCALE" \
  --replay-root "$REPLAY_ROOT" --replay-request "$REPLAY_REQUEST" \
  --ntp-era "$NTP_ERA" \
  --utc-start-ns "$UTC_START_NS" --utc-end-ns "$UTC_END_NS" \
  --verify-replay-source=yes
```

Use `--codec avc` for an AVC replay. The requested interval is half-open
`[start,end)` in integer Unix nanoseconds. The explicit NTP era interprets the
recorder's 32-bit NTP seconds; it is never inferred from the host clock. The native
supported UTC domain is 1970 through 9999. The parser retains exact 128-bit
integers without floating-point conversion.

`--anchor <token>` additionally requires an exact current deployment
authority/effect prefix. This token and `--source-anchor` have different jobs:
the first protects current deployment context; the second identifies the
historical original-source scope. A retained replay receipt is evidence, not
current read authority or proof of deployment membership.

The existing recording catalog selectors keep their established semantics.
`--start-utc-ns`/`--end-utc-ns` with an exact clock companion select declared
node-clock intervals. Recorder assertions use the separate
`--utc-start-ns`/`--utc-end-ns`, replay pins and explicit era shown above. Mixing
these selectors, catalog/discovery/session selectors or decode-tick intervals
with a recorder query is refused.

## MCP

The operator enables source verification when launching the existing stdio
server, alongside its bound deployment, archive and principal:

```bash
fss-mcp --root "$DEPLOYMENT" --archive-root "$ARCHIVE" \
  --principal "$PRINCIPAL" --allow-replay-source-verification
```

Without that launcher flag, recorder UTC calls are refused. The MCP client
cannot grant the permission or override the bound roots or principal. Existing
metadata-only queries do not acquire source-read authority.

Call the existing `query` tool with `target: "recordings"` and these fields:

| Fields | JSON representation |
| --- | --- |
| `codec` | `"avc"` or `"hevc"` |
| `sensor`, `stream` | Exact identity strings |
| `source_anchor`, `receive_clock`, `decode_clock`, `replay_root`, `replay_request` | Canonical `sha256:` strings |
| `generation`, `utc_start_ns`, `utc_end_ns` | Exact canonical decimal strings |
| `ntp_era`, `time_scale` | Exact JSON integers |
| `max_query_windows`, `max_query_samples`, `max_query_packets`, `max_query_results` | Optional exact JSON integers |
| `max_query_source_bytes`, `max_query_read_bytes`, `max_query_io_calls` | Optional canonical decimal strings |
| `anchor` | Optional exact current deployment token |

The closed selector is registered as
[`fss.agent_recording_replay_query.v1`](../schemas/agent_recording_replay_query.v1.json).
The operation and response-envelope versions are unchanged. MCP tool content is
the same canonical JSON as the equivalent CLI request, including refusals.

## Complete bounded results

| Bound | Default | Maximum |
| --- | ---: | ---: |
| Native windows | 64 | 64 |
| Native samples | 16,384 | 16,384 |
| RTP packets | 262,144 | 262,144 |
| Reserved original source bytes | 256 MiB | 2 GiB |
| Matching, unknown and source-only rows combined | 32 | 128 |
| Archive bytes read, including rereads | 1 GiB | 4 GiB |
| Archive I/O calls | 1,000,000 | 4,000,000 |
| Deployment metadata bytes across both observations | 256 MiB | 256 MiB |
| Deployment metadata reads across both observations | 65,536 | 65,536 |
| Complete canonical response | 256 KiB | 256 KiB |
| Cooperative execution deadline | 60 seconds | 60 seconds |

The `--max-query-*` CLI options map to the MCP fields above. Source-byte
reservation and actual filesystem read accounting are separate limits. Archive
read budgets are split between receipt/index metadata and original verification;
the metadata share is at most 64 MiB and 100,000 calls. Counters do not refill
between windows or revalidation phases. Very small allowances are accepted as
requests and fail closed before exceeding the declared work.

A successful response includes every native matching sample, every unknown
sample and every trailing HEVC source-only group. Unknown and source-only rows
consume the same result allowance even if they cannot be located in the UTC
interval. Known samples outside the interval remain an explicit count. Exceeding
any native, context or complete-output bound refuses the whole response; no
successful prefix is returned and no unknown row is dropped to make space.

Each row preserves its native recording root, decode/presentation coordinates,
RTP sequence span, packet-set digest and time-proof digest. Recorder header flags,
raw NTP values and stable malformed/conflicting/missing-evidence reasons remain
visible. Query, report and index identities match the native archive query for
the same pins and native query limits.

## Authority and current deletion checks

The reference entry point is
`agent_recording_context::replay::query_recordings_replay_in_deployment`.
It requires an opaque borrowed `ReplaySourceReadPermit` derived from a real
`ContextAuthority` with both `CAP-AGENT-QUERY-001` and `CAP-READ-MEDIA-001`, matching
principal, source anchor and generation, sufficient declared read allowances,
and current cancellation/deadline admission. The permit binds the complete
native request and read limits; an audit principal or historical receipt cannot
construct it.

The read sequence verifies current deployment metadata, admits the exact replay
receipt, checks the entire receipt reference closure against current deployment
deletions, and only then opens native original roots/indexes and payloads. Native
verification retains receipt, index, root and tombstone observations for final
revalidation. A second deployment observation must match the first authority,
effect prefix, layout and deletion state before pure response projection.

The reader opens no publisher or recovery path. Queries may run while an archive
writer holds its ordinary lock. Changed selected source evidence, corruption,
deletions, stale deployment pins or cancellation refuse instead of yielding
cached rows. Separate owner observations do not constitute an atomic filesystem
snapshot or a future lease.

## Meaning and validation limits

The UTC intervals describe recorder-supplied assertions verified against the
retained datagrams. Their enclosure accounts for integer rounding. Source custody
does not authenticate the recorder clock or bound its physical error. Camera
exposure time, uninterrupted recording, physical activity and physical absence
remain unknown. PLAY ranges, RTP timestamps and arrival times do not fill missing
UTC assertions. A source-only HEVC group is not a published picture.

The actual storage/custody/AVC/HEVC component suite passes **95 tests**, including
all nine read-only replay UTC regressions and pre-original admission denial,
allowance and malformed-receipt checks. It compiles the production source modules; it does not substitute
an implementation. The new deployment-context and canonical CLI/MCP contracts
are authored but remain pending execution: both a native full-graph attempt and
a single-compiler-thread metadata-only attempt were killed in unchanged
Asupersync 0.5.0 before the new context and CLI code compiled. Component passes do
not establish full runtime or CLI/MCP qualification.

Run `bash scripts/check_recording_lifecycle.sh replay` on a host able to compile
the pinned runtime. Repository-owned local DSR qualification and owned-recorder
interoperability remain required. VIT-008, VIT-015 and VIT-022 remain open; this
query adds canonical access to one exact receipt, without claiming multi-recorder
search, calibrated clocks or proof of complete historical retrieval.

See also the [native archive query](RECORDER_TIMESTAMP_QUERY.md) and
[query from an imported retained replay](RETAINED_RECORDER_TIMESTAMP_QUERY.md).
