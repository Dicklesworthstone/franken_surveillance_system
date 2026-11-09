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
- The cumulative selected-source read-byte and filesystem-call limits for approved
  execution, separate from retained-original byte quotes.

Append `--approve sha256:PLAN_HEX` to the unchanged arguments to execute.
The command reruns the protected metadata query and compares the resulting
approval before opening the destination for mutation. The reference
core revalidates again under the existing destination owner before staging a
selected window. The source archive is accessed through a read-only pinned reader;
no archive writer handle is opened.
A changed catalog, publication, tombstone, protected deployment prefix, source
scope, selection, principal, path or budget invalidates the approval.

`--deployment-anchor ANCHOR` optionally requires a particular current deployment
token. The historical `--anchor` is the recording source anchor; the two are
different coordinates.

The owner, original-read and retention acknowledgements are required separately.
They are local operator declarations, not remote authentication or a FLDT media
grant. Later native decode and review still apply current destination privacy
masks.

### Operator format and approval migration

The command emits `fss.rtsp_query_import_operator.v2`. Its approval domain is
`fss.rtsp_query_import_cli_plan.v2`, which binds the selected-source read strategy
and all six source-reader limits in addition to the existing exact selection,
operator scope and deadline. A previously issued v1 CLI approval must be replaced
by a new preview and approval. Changing the JSON format label is not an approval
migration.

The reference core's `fss.rtsp_query_import_plan.v1` encoding, native child
request/proof encodings and retained import identities are unchanged. Existing
publisher-backed reference APIs remain available; the CLI uses the new pinned
reader APIs. Previously retained children can therefore be reconciled through
their existing native identities after a fresh approval.

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

Before issuing an approval, the CLI checks the pinned-source admission floor:
three maximum native-window byte passes per selected window plus its declared
descriptor bytes. Preview reports this as `minimum_source_work` alongside
`maximum_work`. This conservative source reservation does not guarantee that
later reconstruction and publication work will fit the remaining budget.

**Approved source reads are limited to selected native closures.** The CLI uses
one read-only `PinnedClosureReader` across the complete selection. It reads the
exact published window root plus its four native source/index/init/media children,
runs native codec replay, and rehashes the selected closure before publication.
Root bindings and selected deletion markers are rechecked; pending or indeterminate
selected state refuses acquisition. The reader creates no archive paths, takes no
archive writer lock, scans no spool inventory and performs no archive recovery.
An unrelated corrupt payload does not block a selected intact closure. Required
catalog/member metadata and deletion checks still cover the complete query scope.

Selected payload work scales with selected bytes. Completed window payloads are
not reread while processing later windows. The existing publisher's recovery
verification remains unchanged for operations that open that publisher.

For `n` selected windows, `B` declared selected-original bytes and largest window
size `M`, the fixed source allowance admits `n` roots, `5n` objects, `4n` edges,
an object payload no larger than `M`, at most `2B + M + 32768n` charged read bytes,
and at most `1024n + 16` filesystem calls. This includes both integrity passes,
bounded-read reservation slack and final source-layout checks. Each native window
remains bounded to 32 MiB; allowances never refill between windows. See
[exact-pin recording retrieval](PINNED_RECORDING_READS.md) for the component
contract and executed evidence.

The preview's `quoted_original_bytes` prices retained original payloads, not total
I/O. Results separately report `source_read_bytes` and `source_io_calls`. Protected
metadata queries and destination recovery retain their own bounds and are outside
those source-reader counters. Native `work_used` also charges codec replay,
descriptor verification, reconstruction and publication; it is a different account
from filesystem calls. The destination still opens its existing mutation owner.

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

For conditional UTC selection across independent capture sessions or a complete
source namespace, use [UTC query acquisition](RTSP_UTC_QUERY_IMPORT.md). UTC
predicates have a separate explicit clock contract; they are not decode ticks.

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
external effects. Approved destination opening can still complete its local
publication recovery; the source archive is never recovered by this command.

A final source-layout or cancellation refusal can occur after all children have
returned complete receipts. That result still has `complete: false`, retains every
completed receipt, and reports no uncertain current import. It is not permission
to discard the completed prefix or infer that the batch rolled back.

The operator plan/result is not a new retained catalog object or remote
reviewer grant. Retained derivative custody, current payment-zone attestation,
grant expiry/revocation and remote delivery remain separate functionality.

## Regression coverage and qualification status

The reference contracts exercise selected AVC/HEVC native custody, descriptor
revalidation, aggregate refusal/cancellation, stale context, partial progress,
empty selection and retry semantics. CLI contracts exercise the actual binary's
read-only preview, wrong/stale approval refusal, selected-window retention,
fresh-approval reuse and cold native verification.

The pinned-source component target passes **50 tests**, including actual AVC/HEVC
packet replay, parity with the writer-backed loader while its lock is held,
unrelated-corruption isolation, cumulative read bounds, selected tombstones and
dynamic revocation during final rehash. It directly includes the production
storage and recording modules. Its
[retained test log](validation/2026-11-09-pinned-recording-native-tests.log) does
not claim execution of `ReferenceDeployment`, the retained-import adapter or CLI.

The existing twelve reference query-acquisition contracts now have two additional
pinned-reader contracts for native identity parity and cumulative multiwindow
accounting. Parser and actual-binary process contracts are authored and
source-reviewed, including execution while the source writer remains locked.
These full reference/CLI tests have **not been typechecked or executed**: earlier
full-reference metadata builds were killed while compiling unchanged Asupersync
0.5.0, before project diagnostics. Pinned scoped rustfmt and whitespace checks pass.
No substitute runtime or weakened feature gate was used. Native component evidence
does not qualify the complete acquisition command or a release. Pending commands
on a capable pinned-nightly host are:

```sh
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-reference \
  --test rtsp_catalog_import_contract query_acquisition::
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --bin fss-import-rtsp
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-cli \
  --test rtsp_import_cli query::
```
