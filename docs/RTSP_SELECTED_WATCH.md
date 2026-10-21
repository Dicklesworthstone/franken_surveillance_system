# Analyze selected retained RTSP recordings

`fss-watch-rtsp-selected` connects native RTSP custody to whole-recording zone
watch in one approved operation. Supply an ordered list of one through sixteen
exact window, catalog, or catalog-page selections. The command imports every
selection through the existing source-verifying AVC/HEVC importer, then analyzes
each complete retained recording. All analyses use the destination anchor after
the last import.

Each outer selection starts a new foreground model and tracker. A catalog or
ordered page selection preserves the existing continuous native analysis range
inside that selection, including across storage-window and page boundaries.
The command does not infer continuity between separate selections. Its output is
an inventory of candidate observations; event and alert publication remain
separate actions.

## Select the original recordings

Use exact durable pins and scope identities returned by the capture/archive
owner. The input is the same option-array format accepted by
`fss-import-rtsp batch --requests`: a JSON array containing one option/value
array per selection. Each child is an ordinary `fss-import-rtsp` request.

| Source selection | Child options |
| --- | --- |
| One complete recording window | `--window-slot SLOT --window-root sha256:ROOT` |
| One complete catalog | `--catalog-slot SLOT --catalog-root sha256:ROOT` |
| Ordered complete catalog pages | `--catalog-pages 'SLOT@sha256:ROOT,SLOT@sha256:ROOT'` |

Catalog requests also carry the existing decode-clock and time-scale inputs.
See [Complete RTSP catalog import](RTSP_CATALOG_IMPORT.md) for native continuity
checks, page limits, source closure and clock interpretation. Both `--codec avc`
and `--codec hevc` are supported without codec sniffing or fallback.

All children must name the same archive, destination deployment, site and
principal. Every child must explicitly authorize original reading and retention
and provide `--capture-start-ns` with `--capture-uncertainty-ns`. These capture
times remain operator assumptions. A camera receive clock never supplies an
implicit capture origin.

The outer operation owns the import work allowance and deadline. Child
`--approve`, `--max-work` and `--timeout-ms` options are refused. Child source
and media admission bounds remain effective. Exact duplicate native requests
are refused before any file is opened; overlapping selections with different
request identities remain independent analyses and do not imply campaign
deduplication.

## Preview and approve

For example, replace the digest placeholders and scope values below with the
exact values from one owner-selected window. Add further child arrays to select
additional recordings.

```bash
SELECTIONS_JSON='[
  [
    "--archive", "/srv/fss/archive",
    "--root", "/srv/fss/deployment",
    "--site", "site:example",
    "--window-slot", "window-000001",
    "--window-root", "sha256:WINDOW_ROOT",
    "--codec", "avc",
    "--sensor-id", "sensor:camera",
    "--stream-id", "stream:camera",
    "--generation", "1",
    "--anchor", "sha256:SOURCE_AUTHORITY_ANCHOR",
    "--receive-clock", "sha256:RECEIVE_CLOCK",
    "--receive-time-ns", "1000000000000",
    "--capture-start-ns", "999000000000",
    "--capture-uncertainty-ns", "1000000",
    "--owner-authorized", "yes",
    "--read-originals", "yes",
    "--retain-originals", "yes"
  ]
]'

fss-watch-rtsp-selected \
  --requests "$SELECTIONS_JSON" \
  --interpretation ycbcr \
  --zone entrance:0,0,640,480
```

The digest placeholders are not literal valid input. Capture times and the
image-space zone must also come from the operator's reviewed assumptions.

Without `--approve-import`, the command emits a pure plan: it opens no source
or destination files, locks, clocks or network connections. The preview includes
all native source plans, source and destination ownership, detector/tracker
settings, per-selection limits, aggregate reservations and an
`approval_digest`. Repeat the exact arguments with:

```bash
--approve-import sha256:RETURNED_APPROVAL_DIGEST
```

Changing the ordered source selection, any source pin or scope, capture timing,
destination, principal, zone, threshold, budget, screening choice or deadline
changes the approval. An individual import approval cannot authorize this
combined operation.

Approved execution opens the existing archive and the destination owner, verifies
and retains all selected originals, and runs native whole-recording analysis.
The archive and destination must be distinct, non-nested stores. Opening the
archive uses its existing publication lock and can finish pending publication
recovery. Originals remain locally retained and unencrypted. Current destination
sensor privacy masks apply before perception.

## Work bounds and results

`--max-work` supplies one import work account for the complete invocation.
The account is never renewed between selections. Watch limits are fixed per
selection, and their complete sums are admitted and shown before I/O. Those
reservations include sample ceilings, original and reconstructed-media bytes,
source-read bytes, foreground pixel work, the separate opt-in screening pixel
allowance, assignment work and trace bytes. A selection
cannot borrow another selection's unused analysis allowance.

| Bound | Default or hard maximum |
| --- | ---: |
| Outer selections | 1–16 |
| Input JSON | 48 KiB |
| Complete plan preview | 128 KiB |
| Shared import work | Default 1,000,000,000,000 units |
| Cooperative operation timeout | Default 30,000 ms |
| Aggregate trace reservation | At most 128 MiB |
| Complete result JSON | At most 16 MiB + 64 KiB |

Use `--help` for native decoder, read, pixel, assignment, trace and detector
threshold options. `--screened yes` enables the existing conservative visual
health screening. `--tolerate-decode-refusals yes` explicitly selects native
tolerant handling; refusal and gap semantics remain visible in the watch report.
The shared `--max-pixels` option admits 256 through 4,194,304 pixels. AVC's
coded-macroblock allowance is rounded down to a multiple of 256 pixels, so a
nonmultiple never expands the approved ceiling; the preview shows the effective
AVC and HEVC coded-pixel bounds.

The deadline is checked at custody and analysis boundaries, including after
each analysis and before releasing the result. A single native analysis is
work-bounded and cooperatively cancellable through `ReplayCx`; this CLI timer
does not preempt an individual decoder or analysis operation midway.

Successful JSON identifies every selected request and pin, original sensor and
clock scope, operator capture assumptions, retained import identity and proof,
window/page/frame counts, retry reuse status, and its complete native watch
report. It records the common final analysis anchor and explicitly marks
selection order as owner supplied. Candidate observations are source linked and
retain their native uncertainty.

The selection is finite. It does not prove that every connection attempt or
recording in a campaign was included, explain omitted or empty attempts, certify
scene absence, or authorize an alert. Tracking identities belong to their own
selection and native recovery epoch. No camera connection is resumed.

## Failure and exact retry

Import publication is incremental. A failure in a later source, analysis,
deadline check or output write can leave earlier imports durable. Retain the
archive and destination, then repeat the same approved plan. Existing native
reconciliation verifies and reuses completed imports and resumes supported
partial publication; analysis is recomputed with independent state against the
final destination anchor.

A damaged or revoked source is a refusal, not permission to skip a selection,
erase earlier evidence, widen the source scope or return a partial successful
candidate inventory. An oversized report likewise refuses instead of silently
truncating selections or candidates.
