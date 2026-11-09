# UTC review across independently pinned capture sessions

`fss query --target recordings --sessions` and the MCP query tool can inspect one UTC
interval across up to eight native capture sessions of the **same exact sensor and stream**.
Each input keeps its own codec, source generation, source anchor, receive/decode clocks,
catalog pages and retained clock companion. AVC and HEVC inputs may coexist.

The query verifies the complete explicit input union under one archive read allowance,
bracketed by current deployment metadata and deletion checks. It reads no media payload,
opens no writable publisher and performs no recovery, source acquisition or hydration.
This is implemented reference functionality; native compilation and execution remain
unverified under the documented unchanged-Asupersync compiler SIGKILL.

## Exact caller input

The `--sessions` argument is a literal JSON array, bounded to 64 KiB before parsing. It is
never interpreted as a path or read from stdin. Supply each independently verified source
and publication pin; the query does not look up a latest clock or infer a source generation.
Each object has exactly these eleven fields. This shape is a template: replace the angle
bracket placeholders with actual retained identities before use.

```json
[
  {
    "codec": "avc",
    "sensor": "sensor:front",
    "stream": "stream:main",
    "generation": "7",
    "source_anchor": "sha256:<64 lowercase hex digits>",
    "receive_clock": "sha256:<64 lowercase hex digits>",
    "decode_clock": "sha256:<64 lowercase hex digits>",
    "time_scale": 90000,
    "catalogs": [
      {"slot": "<exact catalog publication slot>", "root": "sha256:<64 lowercase hex digits>"}
    ],
    "clock_slot": "fssrc1-avc-<exact source-scope digest>",
    "clock_root": "sha256:<64 lowercase hex digits>"
  }
]
```

Add further complete objects for the other capture sessions. `generation` is an exact
canonical decimal **string**, preserving the full `u64` range. `time_scale` is a positive
JSON integer within `u32`. Every catalog array contains one through eight exact `{slot,root}`
objects. Duplicate object keys, unknown fields, missing fields, noncanonical numbers,
repeated scopes/publication pins and mixed sensor/stream identities are refused before
archive I/O. A retained clock must join its own complete catalog universe, including
windows outside the selected UTC interval.

```sh
fss query --target recordings --json \
  --root /path/to/deployment --archive-root /path/to/archive \
  --sessions "${SESSIONS_JSON:?supply the complete literal pin array}" \
  --start-utc-ns "${START_UTC_NS:?inclusive Unix nanoseconds}" \
  --end-utc-ns "${END_UTC_NS:?exclusive Unix nanoseconds}" \
  --max-windows 32 --max-hydration-bytes 1073741824
```

Optional `--anchor` pins the **current deployment** prefix; it does not replace any
historical `source_anchor` inside the array. The top-level `--codec`, source/clock fields,
`--catalog-slot`, `--catalogs`, `--discover-catalogs` and decode-tick bounds cannot be mixed
with `--sessions`. Existing singleton, catalog-set and discovery forms retain their
original semantics and identities.

For MCP, call the existing `query` tool with `target: "recordings"`, a structured `sessions`
array of the same shape, and exact decimal-string `start_utc_ns`/`end_utc_ns`. Optional
`max_windows` is a JSON integer and `max_hydration_bytes` is a decimal string. The deployment
root, archive root and principal remain fixed by server launch; request fields cannot
replace them. MCP's complete-frame bound also remains in force.

## Result meaning

Sessions are normalized into canonical session-digest order; rows within each session keep
native decode order. Reordering input sessions or catalog pins cannot change request or
decision identity. The output is not a global chronological ordering or proof that the
independent clocks agree.

Each session retains its original clock root, approval identity, correlation policy,
offset interval, observation-bracket count and source scope. A selected window identifies
its session and every supporting catalog membership. The renderer provides bounded H0
metadata handles and the existing native `fss/1` proof/context envelope. Complete unselected
catalogs remain verified and bound through the session and decision identities.

A window without a clock annotation remains `clock_unavailable` under **every** UTC
interval. It consumes the aggregate output count and whole-window hydration quote just
like a timed candidate. If all necessary rows or their proof context do not fit, the whole
query refuses; it never omits an unknown-time session or returns a partial successful union.
Within one source, overlapping catalog membership preserves every location while counting
one unique window once. Aliasing a window root or slot across distinct sessions refuses.

The result preserves both per-session conditional gaps and gaps outside the union of the
known declared envelopes. Unknown-time windows may overlap any of those gaps. These are
statements about the exact supplied metadata, not synchronized-camera coverage, continuous
recording, physical absence or proof of why footage is missing. Unpinned sessions and
catalogs were not searched. Source payload availability and camera exposure time remain
unknown because the query does not replay the media.

## One aggregate work allowance

The implementation shares the existing catalog verifier and UTC selection owner rather
than chaining complete public queries. One `PinnedMetadataReader` covers every input and
finishes only after all sessions, including early and unselected sources, have been read.
Publication roots, typed metadata and every referenced tombstone observation are then
revalidated under the original allowance. No session receives a renewed byte or I/O budget.

| Bound | Native default/ceiling | Protected CLI/MCP |
|---|---:|---:|
| Capture sessions | 8 | 8 |
| Catalog pins per session | 8 | 8 |
| Indexed descriptors per session | 64 | 64 |
| Indexed descriptors across all sessions | 512 | 512 |
| Selected windows, including unavailable clocks | 64 | 32 |
| Publication roots | 584 | 584 |
| Metadata objects | 656 | 656 |
| Referenced edges | 16,384 | 16,384 |
| Bytes in one metadata object | 16 MiB | 16 MiB |
| Archive metadata read bytes, including revalidation | 64 MiB total | 64 MiB total |
| Archive filesystem calls | 160,000 total | 160,000 total |

These ceilings are independent. Every catalog membership consumes descriptor work even
when it refers to an already selected same-session window. Narrower library limits remain
available. A later source with no selected candidates must still verify its complete clock
join and custody, even if earlier sources exactly consumed the output or quote allowance.

The protected wrapper has a separate cumulative deployment allowance of 256 MiB and
65,536 metadata payload reads across its before/after observations. It requires the same
authority/effect-history token, layout and deletion state after the native read, and applies
current deletion restrictions to the full native reference union, including sources that
contributed no output. The two owners are independently checked; this is not an atomic
cross-owner filesystem snapshot. Final JSON remains bounded to 256 KiB, with atomic refusal
when the complete native proof/context would exceed it.

## Verification scope

Native, protected-context, parser, MCP and CLI process contracts cover mixed codecs and
source generations, canonical ordering, independent clock policies and gaps, unknown-time
quotas, exact aggregate limits, all-input custody and late mutation/deletion. Existing
single-source query semantics remain covered by equivalence contracts.

Pinned formatting, schema/registry checks and source review are separate from execution.
The shared host killed unchanged Asupersync before compiling the edited FSS paths, so no
passing native build or executed integration result is claimed for this extension. See
`IMPLEMENTATION_STATUS.md` for the complete validation record.
