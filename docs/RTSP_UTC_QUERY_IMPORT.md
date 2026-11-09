# Acquire native recording candidates by conditional UTC

`fss-import-rtsp query-utc` connects protected UTC recording queries to approved
retention of their selected whole native windows. It supports independently
pinned capture sessions and complete discovery within one historical source
namespace. Each selected AVC or HEVC window is verified and retained through the
existing native import profile, with its original source closure and import identity.

UTC selection uses retained **conditional node read/admission envelopes**. It does
not establish camera exposure time, authenticate UTC, equate independent source
clocks or trim recordings to the requested interval. Windows without clock evidence
remain explicit candidates for every UTC predicate. Every resulting native import
keeps `capture_time_label: "unknown"`.

The command is local and requires an existing deployment and archive. The archive
and deployment must be distinct, non-nested stores. It grants no network, remote
reviewer or media-disclosure authority.

## Choose the source universe explicitly

### Independently pinned capture sessions

Use `--sessions` with the same strict literal JSON array accepted by
`fss query --target recordings --sessions`. It admits one to eight sessions of
one exact sensor and stream. Sessions may have different native codecs, source
generations, receive clocks, decode clocks and time scales. Each session names one
to eight exact catalog pins and its own retained-clock slot/root.

This example shows the selector shape. Replace every `*_HEX` placeholder with
the actual 64 hexadecimal digest digits and use the original source, slot and
generation values from the retained capture. Catalog and clock slots must bind
the supplied roots; the command does not infer a latest root or generate missing pins.

```sh
FSS_SESSIONS='[
  {
    "codec": "hevc",
    "sensor": "sensor:camera-1",
    "stream": "stream:camera-1",
    "generation": "1",
    "source_anchor": "sha256:SOURCE_ANCHOR_HEX",
    "receive_clock": "sha256:RECEIVE_CLOCK_HEX",
    "decode_clock": "sha256:DECODE_CLOCK_HEX",
    "time_scale": 90000,
    "catalogs": [
      {"slot": "ACTUAL_CATALOG_SLOT", "root": "sha256:CATALOG_HEX"}
    ],
    "clock_slot": "ACTUAL_CLOCK_SLOT",
    "clock_root": "sha256:CLOCK_ROOT_HEX"
  }
]'

fss-import-rtsp query-utc \
  --archive /srv/fss/archive --root /srv/fss/deployment --site site:shop \
  --sessions "$FSS_SESSIONS" \
  --start-utc-ns 1794182400000000000 --end-utc-ns 1794182490000000000 \
  --receive-time-ns 1794182500000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

`generation` is an exact decimal JSON string; `time_scale` is a positive JSON
integer. Duplicate or unknown fields, mixed sensor/stream identities, repeated
source/publication pins and incomplete sessions are refused. The selector is a
literal argument bounded to 64 KiB, not a filename. Session and catalog input
order is canonicalized; output session order is pin-digest order, not an asserted
physical chronology. No separate `--codec` or source-scope options accompany
`--sessions`.

### Discover one complete historical namespace

Use `--discover-catalogs yes` when the source namespace is known but its canonical
catalog pages should be discovered. The historical source scope and retained-clock
pin remain explicit. Set the variables below to the actual capture pins before use.

```sh
fss-import-rtsp query-utc \
  --archive /srv/fss/archive --root /srv/fss/deployment --site site:shop \
  --discover-catalogs yes --codec hevc \
  --sensor-id sensor:camera-1 --stream-id stream:camera-1 --generation 1 \
  --anchor "$FSS_SOURCE_ANCHOR" --receive-clock "$FSS_RECEIVE_CLOCK" \
  --decode-clock "$FSS_DECODE_CLOCK" --time-scale 90000 \
  --clock-slot "$FSS_CLOCK_SLOT" --clock-root "$FSS_CLOCK_ROOT" \
  --start-utc-ns 1794182400000000000 --end-utc-ns 1794182490000000000 \
  --receive-time-ns 1794182500000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Discovery verifies the complete bounded canonical namespace, its pages and member
metadata, and its join to the exact retained clock. It preserves an inventory
digest and refuses an incomplete universe. Directory entries are enumerated under
the existing discovery allowance; original payloads are not read during discovery.
Other generations and namespaces are not searched. Discovery and `--sessions` are
mutually exclusive modes.

## Preview and approve

Without `--approve`, both commands return a protected metadata preview with no
source-media reads, writer open, destination creation or recovery. The output
format is `fss.rtsp_utc_query_import_operator.v1`. It contains:

- `approval_digest`, the exact core `plan_digest`, protected query identities and
  current `deployment_anchor`.
- Every selected complete window and its original source/clock coordinates,
  catalog memberships, optional clock ordinal and conditional UTC envelope.
- All independent source contexts, original clock policies and uncertainty,
  per-session gaps and the aggregate conditional gaps.
- The count of `unknown_clock_candidates`, complete retained-original byte and
  frame quotes, acquisition bounds and fixed cumulative source-read limits.

Inspect this complete preview and rerun the unchanged arguments with
`--approve "$FSS_APPROVAL_DIGEST"`, setting that variable to its `approval_digest`.
The command recomputes the preview and checks the approval before opening the
existing destination for mutation. The reference owner then revalidates the full
protected metadata decision under that destination owner before importing a child.
Current original-read and retention authority is checked at native action boundaries.

The core plan uses `fss.rtsp_utc_query_import_plan.v1`; the CLI approval uses
`fss.rtsp_utc_query_import_cli_plan.v1`. It binds exact owner paths, principal,
source/catalog/clock pins, metadata allowances and decisions, conditional time
interpretation, selected child requests, acquisition bounds, source-read strategy
and limits, current deployment prefix and cooperative timeout. A changed context
requires a new preview and approval.

`--principal` defaults to `principal:local-operator`. The three separate `yes`
acknowledgements are required local operator declarations; they do not authenticate
a remote caller. `--deployment-anchor ANCHOR` optionally pins the current deployment
authority/effect-history token. In discovery mode, `--anchor sha256:...` is the
historical recording source anchor. These two anchors are separate coordinates.

The command refuses a preview larger than 192 KiB before mutation, preserving
64 KiB of its 256 KiB output ceiling for complete native result receipts. It never
silently truncates selected rows, clock uncertainty, catalog memberships or gaps.

## What UTC selection means

The requested interval is half-open Unix nanoseconds: `[start, end)`. Retained
node-observation envelopes have inclusive earliest/latest bounds. Integer time
values are preserved losslessly; JSON output represents these coordinates as
decimal strings.

| Observation | Selection and retention behavior |
|---|---|
| A declared conditional UTC envelope overlaps the request | The complete native window is a candidate and consumes the shared bounds. |
| The window has no retained clock annotation | `clock_state` is `clock_unavailable`; the complete window remains a candidate even for an otherwise unrelated UTC interval. |
| Every known envelope misses an interval and there are no unknown-clock candidates | A complete empty selection may be returned with explicit conditional gaps. |
| Source, clock, inventory, deletion or budget verification fails | The command refuses; failure is not an empty or partial successful query. |

The report retains `trusted_utc: false`,
`packet_to_clock_correspondence_replayed: false` and
`clock_equivalence_assumed: false`. Native acquisition verifies original packet
custody and codec reconstruction; this route does not separately replay the retained
clock index's admission coordinates against those packets. The original clock
assertions, uncertainty and metadata-only interpretation remain visible.

A conditional gap says that the verified metadata supplies no clock-annotated
candidate for that interval. Unknown-clock windows may overlap it. It does not
establish a missing-footage cause, uninterrupted camera coverage, physical absence
or tracking continuity. Capture hints, decode-tick predicates, individual window
selectors and whole-catalog composition flags are outside this UTC command.

## Whole-window custody and bounded source access

Each candidate is imported under its unchanged native AVC/HEVC request and proof.
The complete original recording root plus source RTP, index, initialization and
media children are retained. Full descriptor equality is checked after actual
native source replay and before destination publication. Reconstruction uses the
window's original sample timing; it never substitutes an assumed frame rate.

The requested UTC interval does not trim original custody. The destination does
not receive a partial catalog or clock root whose unselected source children are
missing. Conditional selection provenance remains in the operator plan/result,
while the native import receipt identifies independently retained source evidence.
Preserve those plan/result receipts when the UTC selection provenance is needed
later; this route does not create a new retained clock companion or review artifact.

Both UTC and [decode-clock acquisition](RTSP_QUERY_IMPORT.md) use one pinned
read-only source reader across the entire selection. There is no archive writer
lock, spool inventory scan or recovery. The reader verifies exact published root
bindings, selected deletion state, all five objects and actual codec replay, then
rehashes that closure. Unrelated corrupt source payloads do not block selected
intact windows; required metadata still must verify. Destination mutation retains
its existing recovery and custody rules.

For `n` selected windows, total original payload `B` and largest window `M`,
`source_read_limits` fixes `n` roots, `5n` objects, `4n` edges, maximum object size
`M`, `2B + M + 32768n` charged read bytes and `1024n + 16` filesystem calls.
These allowances cover both read passes and bounded-read reservation slack without
refilling. Earlier completed payloads are not reread when later windows are loaded.
The final source-layout/cancellation observation is included in reported usage.

`quoted_original_bytes` is a retained-payload quote. Actual `source_read_bytes`
and `source_io_calls` are reported separately; protected metadata and destination
work are outside those source-reader counters. Native `work_used` includes a
conservative three maximum-window byte-pass reservation per selected window plus
descriptor, reconstruction and publication charges. A minimum reservation check
does not guarantee that all later native work fits the supplied ceiling.

| Option | Default / maximum |
|---|---|
| `--max-windows` | 32 complete candidates across all sources |
| `--max-hydration-bytes` | Defaults to the original-byte allowance; may not exceed it |
| `--max-frames` | 16,384 complete native samples |
| `--max-original-bytes` | 134,217,728 bytes |
| `--max-media-bytes` | 67,108,864 reconstructed bytes |
| `--max-work` | Defaults to 1,000,000,000,000; maximum 1,000,000,000,000,000 |
| `--timeout-ms` | Defaults to 30,000; maximum 600,000 |

The first five rows are ceilings that may be narrowed. Each native window remains
bounded to 32 MiB. Timeout is cooperative at bounded action and I/O boundaries.

## Partial progress and later review

The batch is not atomic. Results retain complete child import identities, roots,
proofs and original conditional selection coordinates. On failure, `complete` is
false, `next_window` identifies the next or uncertain candidate, and
`failed_import_may_be_durable` distinguishes a lost current receipt from a refusal
before publication. The process exits unsuccessfully for an incomplete batch.

A final source-layout or cancellation refusal can occur after all child receipts
are known. It returns the entire durable prefix, `next_window` equal to its length,
and no uncertain current import. Completed children remain retained.

After partial progress or a lost response, rerun the same preview without approval
and inspect its new current-state digest. Approving that digest reconciles unchanged
native child identities and reports them with `reused: true`. An old deployment-bound
approval becomes stale after successful mutation. This existing-only destination
path does not reconcile unrelated pending external effects.

Returned `import_identity` values work with retained verification, native decode
and [movie selection](RETAINED_MOVIE_SELECTION.md). Movie presentation ticks must
come from the retained movie's time basis; a UTC predicate is not a movie-tick
range. Current privacy masks apply to later review. Grant-bound trimmed exports,
current payment-mask attestations, retained derivative custody, expiry/revocation
and remote delivery remain separate functionality.

## Evidence and execution status

The pinned native component target passes **50 tests**, including both production
codec replay paths, writer-loader parity while its lock is held, unrelated-source
corruption isolation, selected tombstones, cumulative bounds and dynamic authority
revocation during final rehash. See the
[retained native test log](validation/2026-11-09-pinned-recording-native-tests.log)
and [reader contract](PINNED_RECORDING_READS.md). These tests include the actual
production storage/recording modules, but do not execute `ReferenceDeployment`,
the retained-import adapter or CLI.

Ten UTC reference acquisition contracts, two decode-clock pinned-reader contracts,
six UTC command-parser cases and one UTC actual-binary process case are authored
and source-reviewed. They include independent AVC/HEVC generations, unknown-clock
retention, discovery, cold retained-source verification, exact approval identities,
changed clocks, corruption, current authority, aggregate bounds, partial progress,
stale-approval retry, missing destinations, empty results and late finalization.
Pinned scoped formatting and whitespace checks pass.

The full reference and CLI contracts have **not been typechecked or executed**.
Earlier full-reference metadata builds were killed in unchanged Asupersync 0.5.0
before project diagnostics. No substitute runtime or weakened feature gate was
used. Native component evidence does not qualify this complete command or a release.
Pending commands on a capable pinned-nightly host are:

```sh
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-reference \
  --test rtsp_utc_query_import_contract
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-reference \
  --test rtsp_catalog_import_contract query_acquisition::
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --bin fss-import-rtsp query_utc::tests
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --test rtsp_import_cli query_utc::
```
