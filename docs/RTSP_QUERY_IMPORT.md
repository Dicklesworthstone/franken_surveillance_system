# Query-selected native RTSP acquisition

`fss-import-rtsp query` connects an exact recording-catalog query to approved
retention of the selected whole windows. It removes manual copying of catalog
rows into individual import commands. Every selected window uses the existing
AVC or HEVC source-closed native import profile, immutable identity, original
RTP/index/init/media proof and cold replay path.

This is a bounded, local operator command. It requires an existing deployment,
one exact catalog slot/root, its explicit source and decode-clock scope, and a
nonempty half-open interval. It admits at most 32 selected windows. It does not
turn a metadata query receipt into media access authority.

## Preview, then approve the exact selection

Use the same source pins as the recording query. Paths below are examples;
digests and source identities must come from the operator's actual archive.

```sh
fss-import-rtsp query \
  --archive /srv/fss/archive --root /srv/fss/deployment --site site:shop \
  --catalog-slot catalog-camera-1-0001 --catalog-root sha256:CATALOG_HEX \
  --codec hevc --sensor-id sensor:camera-1 --stream-id stream:camera-1 \
  --generation 1 --anchor sha256:SOURCE_ANCHOR_HEX \
  --receive-clock sha256:RECEIVE_CLOCK_HEX \
  --decode-clock sha256:DECODE_CLOCK_HEX --time-scale 90000 \
  --decode-start 450000 --decode-end 900000 \
  --receive-time-ns 1794182400000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Without `--approve`, the command reads bounded catalog and deployment metadata.
It does not create a deployment, open a writer, perform publication recovery,
read original media, or connect to a camera. The response contains:

- The exact approval digest, core plan digest, current deployment anchor and
  protected query decision.
- Selected catalog ordinals, window slots/roots, full decode intervals,
  requested overlaps, original-byte quotes and frame counts.
- Every indexed gap in the requested interval, including leading and trailing
  gaps.
- Aggregate frame, original-byte, reconstructed-media, work and deadline bounds.

Append `--approve sha256:PLAN_HEX` to the unchanged arguments to execute.
The command reruns the protected metadata query and compares the resulting
approval before opening archive or destination writer handles. The reference
core revalidates again under the opened owners before staging a selected window.
A changed catalog, publication, tombstone, protected deployment prefix, source
scope, selection, principal, path or budget invalidates the approval.

`--deployment-anchor ANCHOR` optionally requires a particular current deployment
token. The historical `--anchor` is the recording source anchor; the two are
different coordinates.

The owner, original-read and retention acknowledgements are required separately.
They are local operator declarations, not remote authentication or a FLDT media
grant. Later native decode and review still apply current destination privacy
masks.

## Selected retention and complete native proofs

The planner selects complete windows that intersect the requested decode interval.
It never truncates compressed data or fabricates an IDR at the interval boundary.
Execution verifies each loaded window against its entire catalog descriptor:
source scope, codec, decode timing, original roots, payload lengths and packet,
sample and NAL counts must agree.

Only selected windows are retained in the destination. The original full catalog
root is not copied into a destination missing its unselected children. Each
selected import keeps the existing native proof and can be cold-verified without
the archive after successful completion.

One aggregate work budget spans all selected windows. Frame, original-byte and
reconstructed-media ceilings are cumulative, not replenished for each child.
A refusal never truncates the selection into a successful shorter result.
No tracker continuity is inferred between the independently imported windows.

**Archive opening remains a separate performance boundary.** The existing
`LocalRootPublisher` performs verified spool recovery and can rehash unselected
archive objects before the selected imports run. The CLI bounds that archive to
65,536 objects and 1 GiB of spool payload. The preview's selected-byte quote
describes selected retained originals; it is not a bound or estimate of total
disk I/O, hashing work, publisher recovery or allocator overhead. Removing that
archive-wide read requires a separately qualified read-only native recording
loader; this feature does not weaken existing recovery verification.

## Timing, gaps and subsequent review

Capture time remains `unknown`. This command refuses capture-start/uncertainty
hints because one catalog-wide timestamp cannot be reused as the independent
origin of every selected window. It also refuses page lists, individual window
selectors and whole-catalog gap-composition flags. Those have their own existing
commands and approval profiles.

The `selected_overlap` values are in the catalog's declared decode clock.
They are not UTC and must not be copied blindly into a movie-presentation query.
The returned `import_identity` is accepted by the existing native tools:

```sh
fss-file verify --root /srv/fss/deployment --site site:shop \
  --import-id sha256:IMPORTED_WINDOW_HEX

fss-file select-movie --root /srv/fss/deployment --site site:shop \
  --import-id sha256:IMPORTED_WINDOW_HEX \
  --start-movie-tick MOVIE_START --end-movie-tick MOVIE_END
```

Choose movie ticks from the retained movie time basis. See
[retained movie selection](RETAINED_MOVIE_SELECTION.md) for exact presentation
intervals, prerequisite decode ranges and current-mask review/export.

Indexed gaps mean this pinned catalog has no matching window for those ticks.
They do not establish why footage is missing, physical absence, continuous
camera coverage or trustworthy UTC. An empty query returns an explicit empty
selection; it is distinct from a refused query.

## Partial progress and retry

The operation is not atomic across windows. Every completed child remains
durable if a later child fails. The structured result includes completed native
import identities, the next window index and whether the current failed import
may already be durable. The process exits unsuccessfully on incomplete execution;
the JSON is still useful reconciliation evidence.

A successful import advances deployment authority, so the old context-bound
approval becomes stale. After partial progress or a lost response:

1. Preserve source and destination stores.
2. Run the same selection without approval against current state.
3. Inspect and approve its new digest.
4. Existing deterministic child identities reconcile already completed imports.

Do not infer rollback, delete completed imports to force a retry, or reuse an old
approval against a new deployment prefix. Destination opening for this path
requires an established deployment and does not reconcile unrelated pending
external effects. Approved archive/destination opening can still complete local
publication recovery.

The operator plan/result is not a new retained catalog object or remote
reviewer grant. Retained derivative custody, current payment-zone attestation,
grant expiry/revocation and remote delivery remain separate functionality.

## Regression coverage and qualification status

The new contracts exercise selected AVC/HEVC native custody, descriptor
revalidation, aggregate refusal/cancellation, stale context, partial progress,
empty selection and retry semantics. CLI contracts exercise the actual binary's
read-only preview, wrong/stale approval refusal, selected-window retention,
fresh-approval reuse and cold native verification.

Twelve new reference contracts, four command-parser cases and one actual CLI
process integration case are authored and source-reviewed. The workspace runner
recovered after implementation; pinned scoped rustfmt and whitespace checks pass.
These reference/CLI tests have not been executed: earlier full reference metadata
builds were killed while compiling unchanged Asupersync 0.5.0, before project
typechecking. No new runtime retry, substitute runtime or weakened feature was
used. Do not treat source review or hosted workflow status as native release
qualification. Pending commands on a capable pinned-nightly host are:

```sh
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-reference \
  --test rtsp_catalog_import_contract query_acquisition::
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --bin fss-import-rtsp
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --test rtsp_import_cli query::
```
