# Native recording metadata through the canonical agent query

`fss query --target recordings` exposes one explicitly pinned native AVC or HEVC recording
catalog through the existing AOP-005 query operation and AVIEW-003 case response. It returns
metadata handles, either half-open decode-clock overlaps or conditional UTC candidates,
indexed gaps and a declared whole-window hydration byte quote. The existing event and completed-file `footage` targets retain their
own grammars.

This is reference functionality. The execution environment was restored on 2026-11-07,
but two exact production checks were killed compiling unchanged Asupersync 0.5.0. Scoped
format/parser and MCP schema checks passed; the authored Rust integration contracts below
remain unexecuted. No release qualification is claimed.

## Exact inputs

Use the source scope and catalog publication slot/root from the native archive's retained
publication. A slot alone, a path, a camera name, or a latest-pointer guess is insufficient.

| CLI option | Meaning |
|---|---|
| `--root` | Existing deployment supplying current protected situation context |
| `--archive-root` | Separately selected existing native object/archive root |
| `--codec` | Exactly `avc` or `hevc`; no codec guessing |
| `--catalog-slot`, `--catalog-root` | Exact published slot and immutable catalog SHA-256 |
| `--sensor`, `--stream`, `--generation` | Original source scope; generation is positive |
| `--source-anchor` | Original recording's authority/metadata digest |
| `--receive-clock`, `--decode-clock` | Exact original clock identities |
| `--time-scale` | Positive decode-clock ticks per second |
| `--start-tick`, `--end-tick` | Decode mode: nonempty half-open decode-clock interval |
| `--clock-slot`, `--clock-root` | UTC mode: exact retained clock companion namespace and SHA-256 |
| `--start-utc-ns`, `--end-utc-ns` | UTC mode: nonempty half-open Unix-nanosecond interval |
| `--max-windows` | Atomic selection ceiling, 1 through 32; default 32 |
| `--max-hydration-bytes` | Ceiling on the declared later whole-window hydration quote |
| `--anchor` | Optional exact current deployment authority/effect-history token |
| `--principal` | Audit label, not authentication or a media-disclosure grant |

`--source-anchor` and `--anchor` represent different owners and different identities.
The former is an original recording pin. The latter is a current deployment precondition.

After setting the variables to actual retained pins, a request has this shape:

```sh
fss query --target recordings --json \
  --root "$FSS_DEPLOYMENT" --archive-root "$FSS_ARCHIVE" \
  --codec avc \
  --catalog-slot "$FSS_CATALOG_SLOT" --catalog-root "$FSS_CATALOG_ROOT" \
  --sensor "$FSS_SENSOR" --stream "$FSS_STREAM" --generation "$FSS_GENERATION" \
  --source-anchor "$FSS_SOURCE_ANCHOR" \
  --receive-clock "$FSS_RECEIVE_CLOCK" --decode-clock "$FSS_DECODE_CLOCK" \
  --time-scale 90000 --start-tick 0 --end-tick 18000 \
  --max-windows 16 --max-hydration-bytes 67108864
```

The numerical interval is illustrative and must be chosen in the pinned catalog's actual
decode clock. It is not a UTC interval. All CLI integers require canonical decimal spelling.
Event predicates, file-import nanosecond predicates, historical deployment selectors,
continuations and hydration flags refuse instead of being reinterpreted.

## UTC candidate mode

To ask for a real-time interval, replace both tick bounds with the complete UTC flag set.
Keep every original catalog, source and clock-scope pin; the retained companion belongs to
that exact source generation and monotonic session. For example, after assigning actual
retained pins and Unix-nanosecond endpoints:

```sh
fss query --target recordings --json \
  --root "$FSS_DEPLOYMENT" --archive-root "$FSS_ARCHIVE" \
  --codec avc \
  --catalog-slot "$FSS_CATALOG_SLOT" --catalog-root "$FSS_CATALOG_ROOT" \
  --sensor "$FSS_SENSOR" --stream "$FSS_STREAM" --generation "$FSS_GENERATION" \
  --source-anchor "$FSS_SOURCE_ANCHOR" \
  --receive-clock "$FSS_RECEIVE_CLOCK" --decode-clock "$FSS_DECODE_CLOCK" \
  --time-scale 90000 \
  --clock-slot "$FSS_CLOCK_SLOT" --clock-root "$FSS_CLOCK_ROOT" \
  --start-utc-ns "$FSS_UTC_START_NS" --end-utc-ns "$FSS_UTC_END_NS" \
  --max-windows 16 --max-hydration-bytes 67108864
```

Mixed tick/UTC bounds, incomplete clock pins and a slot outside the derived clock namespace
refuse. UTC mode uses a separate native request identity; it never fabricates a tick query.
The read reconstructs the retained raw NTP exchange, completed read brackets, signed clock
correction and fixed drift/lifetime policy, then binds every clock row to the catalog before
filtering. A closed declared envelope `[lo, hi]` is a candidate for `[start, end)` exactly
when `hi >= start` and `lo < end`.

Rows without a clock annotation remain explicit `clock_unavailable` handles **regardless of
the requested interval**. They consume the same window-count and whole-window byte-quote
ceilings. If unknown-clock rows alone exceed a ceiling, narrowing time cannot remove them;
the complete bounded query refuses instead of silently dropping potential evidence.

UTC gaps describe portions of the request outside declared node-observation envelopes.
Unknown-clock windows may overlap those gaps. Metadata reconstruction does not replay
original packet/admission coordinates, authenticate the local time server, establish camera
exposure times or certify physical coverage. The output retains these conditions, the full
clock policy and correction interval. H0 handles include clock-index metadata, and proof
pointers include both clock identities and its historical approval digest. That digest grants
no present acquisition, hydration or disclosure authority.

The native trust model and read ceilings are defined in
[the retained clock metadata contract](RECORDING_CLOCK_METADATA_QUERY.md).

## What the result establishes

The native reader verifies the exact catalog publication record, canonical manifest and typed
catalog metadata. The catalog verifier reconstructs each expected recording manifest and the
complete flat reference closure. Every member's exact publication/root metadata is checked,
including members outside the requested interval, and every referenced object's local deletion
markers are checked. Admitted metadata, slots and deletion-marker absence are revalidated
under the same request allowance before return.

Selected rows include recording roots, publication slots, native decode intervals, selected
overlap, declared bytes and sample/packet/NAL counts. Handles allow only H0 metadata. Their
availability describes the verified metadata object, **not source-media availability**.
A later hydration byte quote covers whole selected recordings; it is neither consumption by
this query nor permission to read their payloads.

An indexed gap means this exact catalog has no matching window for that interval. Gap causes,
payload retrievability, camera coverage, physical activity, physical absence and trusted UTC
remain unknown. An empty selection can therefore coexist with a complete bounded catalog
scan and explicit not-observable gaps.

The deployment's metadata-only history is replayed before and after the archive read. Its
authority/effect token, layout and deletion state must agree. Every referenced root and
child, including unselected windows, is checked against current deployment deletion
authority. The response retains the
protected knowledge cells of its situation projection. The archive and deployment are
independently verified owners; this is not an atomic cross-owner snapshot or proof that the
camera is registered in that deployment.

## Read and authority boundaries

This path does not open a publisher, acquire a writer lock, run recovery, scan directories,
contact a camera, or read original packets, initialization/media leaves, or per-window media
indexes. It can inspect metadata while an existing writer lock is held. Missing or corrupt
source-media leaves do not silently become claims of available video.

Missing, malformed, repinned or tombstoned metadata refuses. Cancellation, head changes and
budget exhaustion also refuse; none becomes a truncated or empty successful selection.
The public native API retains typed reasons. The CLI uses the existing query diagnostic or
refusal envelopes and invents no authority anchor when deployment verification fails.

The native library admits at most one catalog with 64 indexed members. CLI/MCP return at
most 32 selected windows; if the interval selects more than its declared limit, narrow the
interval. This slice has no continuation or cross-catalog discovery.

Decode mode shares 8 MiB of archive read bytes and 10,000 filesystem calls across both
passes. UTC mode shares 64 MiB and 20,000 calls across catalog, clock, members and final
revalidation; its larger ceiling admits the existing bounded retained clock format. Deployment context separately shares 256 MiB of metadata payload bytes and
65,536 payload-read attempts across its initial and final replay. The response reports their
combined allowance and consumption while explicitly distinguishing the counter units.
The output ceiling is 256 KiB. The 60-second deadline is cooperative between bounded phases,
not a preemptive filesystem timeout; CPU and full output tokens are not metered.

## MCP

The operator must bind an archive when launching the stdio server:

```sh
fss-mcp --root "$FSS_DEPLOYMENT" --archive-root "$FSS_ARCHIVE" \
  --principal principal:recording-reader
```

Without that launch binding, recording requests refuse. Clients cannot override either root
or the principal. The tool remains `query`; select `target: "recordings"`.

Argument names use underscores: `catalog_slot`, `catalog_root`, `source_anchor`,
`receive_clock`, `decode_clock`, `time_scale`, `start_tick`, `end_tick`,
`max_windows`, and `max_hydration_bytes`. Sensor, stream, codec and optional deployment
anchor keep their names. Generation, tick endpoints and the optional hydration-byte ceiling
are canonical decimal **strings**, preserving their full u64 range. Time scale and the optional
window ceiling are JSON integer numbers. The adapter forwards them through the same native
CLI parser and preserves semantic response bytes and refusal status.

For UTC mode, supply `clock_slot`, `clock_root`, `start_utc_ns` and `end_utc_ns`, and omit
`start_tick` and `end_tick`. UTC endpoints are canonical decimal **strings**, not JSON
numbers. All four UTC fields are required together; both parser and discovery schema
reject mixed axes, missing pins and client-supplied roots or principal.

## Focused contracts

Run these with the repository's pinned compiler and locked dependencies:

```sh
cargo test --locked --offline -p fss-publication --test pinned_metadata_contract
cargo test --locked --offline -p fss-reference --test agent_recordings_contract
cargo test --locked --offline -p fss-reference --test agent_recordings_utc_contract
cargo test --locked --offline -p fss-cli --lib recording_query_cmd
cargo test --locked --offline -p fss-cli --test recording_query_contract
cargo test --locked --offline -p fss-cli --bin fss-mcp
```

Authored cases cover both native codecs; exact scope/root pins; half-open gaps; absent/corrupt
source leaves; writer locks and unrelated staged files; malformed metadata and flat closures;
late tombstones; cancellation; aggregate budgets including revalidation; current protected
deployment context; stale and mid-query authority changes; CLI/MCP grammar separation;
fixed launch bindings; full-width integers; and semantic response preservation.

UTC contracts additionally cover complete clock/catalog binding before filtering, unknown-clock
quota accounting, closed-envelope boundaries, coherently rehashed malformed clock claims,
late deletion markers, full current-deployment context and real-process CLI/MCP response
parity. The standalone discovery schema passed 47 admission/refusal cases; that does not
replace native transport execution.

VIT-008, VIT-015 and VIT-019 remain open. Cross-catalog discovery, source replay through this
agent surface, continuous recording, media hydration and broader quality/coverage qualification
remain separate work.
