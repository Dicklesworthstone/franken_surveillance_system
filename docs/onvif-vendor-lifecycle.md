# Source-linked ONVIF lifecycle claims

The additive `parse_metadata_lifecycle_document` API interprets ObjectTree and
Behaviour declarations from original MetadataStream XML. It provides typed
rename, merge, split and delete claims, plus separate idle and removed flags.
These remain statements made by the vendor analytics module. They do not establish
physical identity, movement, departure, coverage or effect authority.

## Native command

Use exact existing import identities and publication roots from retained XML,
PullPoint, RTP-file or finite native RTP capture receipts:

```sh
fss-onvif-metadata lifecycle \
  --root /absolute/path/to/deployment \
  --site site:lab \
  --xml-source "${IMPORT_ID}@${PUBLICATION_ROOT}"
```

Use `--rtp-source "${IMPORT_ID}@${PUBLICATION_ROOT}"` for an RTP source. Repeat
either flag in the intended order for up to 32 distinct source identities.
Each independently supplied pin is a continuity boundary. A source file used for
the original import is not needed: the query verifies the retained originals.

The complete result uses
[`fss.onvif_vendor_lifecycle_report.v1`](../schemas/onvif_vendor_lifecycle_report.v1.json).
Its main fields are:

| Field | Meaning |
|---|---|
| `tracklets` | Complete original tracks-v1 JSON, including exact source handles, current authority, original groups and cumulative read/work usage |
| `documents` | Every pinned source/document, including frozen-v1, SOAP, rejected, empty and zero-document dispositions |
| `analysis.frames` | Original frame coordinates, declaration positions, row ranges and explicit lifecycle boundaries |
| `analysis.operations` | Ordered Rename/Split/Merge/Delete claims with observed, unresolved or conflicted endpoints and exact supporting occurrences |
| `analysis.behaviours` | Separate Idle/Removed declarations with original object references |
| `analysis.reuses` | Observations of an integer following an explicit vendor Delete claim |
| `snapshot_digest` | Commitment to the complete source-verified query, parser policy, document receipts and analysis |

The original tracklet report digest, groups and occurrence identities remain
unchanged. The enclosing retained snapshot and its usage include the additional
lifecycle work, so they need not equal a standalone `tracks` query's accounting.

Raw module names, integer ObjectIds and vendor UTC strings are null by default.
`--include-values yes` explicitly discloses those values in both nested reports;
UUID strings remain withheld. Digest/source references remain available in either
mode. Output is one complete JSON document bounded to 32 MiB; a query, budget,
cancellation or encoding refusal returns no successful partial result.

All `tracks` source/grouping options are accepted. The lifecycle default shared
`--max-work-units` is 33,554,432; the independent `--max-analysis-work` default is
4,000,000 and `--max-analysis-bytes` defaults to 4,194,304 canonical bytes.
`--max-projection-work` still controls the original tracks projector.
Both declared projection allowances must fit both source passes in the same
outer balance, with additional balance needed for source history, parsing and
receipt work. The lifecycle allowance must also cover genuine tracklet replay
plus the additional interpretation. Invalid or impossible policies fail before
source I/O. The existing request timeout, cancellation and finalization owner
also covers report serialization.

```sh
fss-onvif-metadata lifecycle --help
cargo test --locked --offline -j1 -p fss-cli --bin fss-onvif-metadata
cargo test --locked --offline -j1 -p fss-cli --test onvif_metadata_tracks_cli
```

Two new command-parser tests and three real import-to-lifecycle process tests
are authored. The process fixtures cover unchanged original rows and disclosure,
RTP rejected/empty source receipts, frozen-v1 non-upgrade, limits and missing-store
refusal. These new native tests, the outer JSON envelope and full command remain
**unexecuted** after the genuine Asupersync dependency builds were killed before
FSS diagnostics. The temporary execution outage was recovered; pinned rustfmt,
whitespace checks and a fresh 32-test lineage rerun passed. Independent source review
and static JSON/schema-shape checks passed. These do not replace native integration,
standard JSON Schema validation or release qualification.

## Supported interpretation

The parser follows the bounded integer-reference subset of the official
[metadata stream schema](https://github.com/onvif/specs/blob/development/wsdl/ver10/schema/metadatastream.xsd),
schema version 25.12, exact source blob
`ba3726fef2d3424486883079f9a520ee069698f0`.

| Claim | Supported structure |
|---|---|
| Rename | One lowercase `from`, followed by one lowercase `to` |
| Merge | At least two `from` references, followed by one `to` |
| Split | One `from`, followed by at least two `to` references |
| Delete | An ObjectId reference on the Delete element |
| Idle / Removed | Separate optional Behaviour flags; neither deletes an ID |

The normative endpoint names are lowercase even though some prose examples use
uppercase. Namespace lookalikes and invalid known cardinalities cannot become
supported claims. Missing integer IDs and UUID references remain explicitly
unsupported; UUIDs are never used for matching. Unknown nodes and attributes are
counted and remain available in the original source.

Frames, objects and operations preserve their original order and exact XML child
positions. Integer and timestamp spellings are retained, and private values are
excluded from Debug output. Interpretation preserves repeated claims instead of
coalescing them. Geometry and class fields remain the separate analytics owner's
responsibility.

## Frozen compatibility

The independent generation is `gen:fss1:onvif-vendor-lifecycle-v1`. Existing
event-v1 and analytics-v2 parsing and canonical bytes remain unchanged. In
particular, analytics-v2 still records ObjectTree and Behaviour as uninterpreted
content. Existing retained roots and tracklets-v1 are not silently reinterpreted.
This parser accepts MetadataStream only; SOAP PullMessages is outside its subset.

## Cost and validation

The existing XML limits remain 256 KiB, 4096 nodes and depth 32. Additional
per-document ceilings are 128 frames, 512 objects, 1024 operations and 2048
references. `LifecycleParseLimits` can tighten each ceiling. The public
`lifecycle_parse_work_bound` quotes the full conservative reservation before XML
parsing: eight units per source byte, plus 128 per possible node, plus one. The
hard work ceiling is 4 Mi units. These units describe deterministic admission
accounting, not CPU time. Cooperative cancellation is checked before and after
XML parsing, throughout interpretation and before a successful return.

The actual production parser target passed 28 tests: 24 focused lifecycle cases
and four existing embedded wire tests. The focused cases include frozen-v1/v2
compatibility, normative cardinalities, unknown and missing references, private
diagnostics, all aggregate limits, exact work reservation and every cancellation
cut. Scoped Clippy also passed. These parser results do not establish native
retained-owner execution or physical-device/Profile M qualification.

```sh
cargo test --locked --offline -j1 -p fss-core --test onvif_lifecycle_wire_contract
```

## Retained lifecycle lineage

The public `metadata::lifecycle::RetainedLifecycle::open` API accepts the same
ordered, exact XML/RTP identity-and-root pins as retained tracklets, plus
`LifecycleReadLimits` and the existing `ReplayCx`. It reconstructs all original
sources twice and runs the additive interpretation inside each complete source
pass. It returns the original tracklet snapshot, a complete lifecycle report,
every document disposition and a new retained snapshot digest.

The pure `project_lifecycle` API pairs each original analytics frame with its
lifecycle overlay and the unchanged tracks-v1 report. It first replays the genuine
tracklet projector and requires full equality. It then resolves supported integer
references against the current or immediately preceding eligible frame of the same
named module. Each resolved endpoint includes the exact original occurrence,
tracklet, frame and object position. It does not join or relabel the old tracklets.

Rename, Split, Merge and Delete statements remain ordered occurrences, including
duplicates and competing declarations. Endpoints carry observed, unresolved or
conflicted state and explicit issues. Normative self endpoints such as Merge
`12,17 -> 12` and Split `12 -> 12,17` are supported. Unsupported UUID references
are never matched. Idle and Removed remain separate Behaviour claims. An observed
integer following a vendor Delete produces an explicit reuse relationship.

Separate input pins, generation changes, missing module/object support, vendor
clock regression or excessive gap, transport discontinuity, changed transformations
and genuinely uninterpreted content prevent unsupported linkage. The independent
overlay understands ObjectTree/Behaviour that remain opaque in tracks-v1; it does
not erase other opaque content. Neither observation linkage nor deletion/reuse
establishes physical identity, departure, absence or camera coverage.

### Complete source accounting

Each XML candidate has a receipt with its exact source pin, original document/XML
digest, frozen parser/container, original frame interval and complete interpretation
counts. Empty, rejected and SOAP candidates remain visible. An RTP source with no
complete candidate receives an explicit zero-document row. Frozen events-v1 inputs
are skipped without applying the new parser or discovering analytics frames.

Both complete passes debit the same installed indexed-read allowance and outer
work balance. Additive XML rereads, once-per-document RTP hashing, conservative
parser quotes, the entire independent projector reservation and receipt hashing
are charged to that balance. Parser work is narrowed to the source quote only
after checking the caller's cap. Aggregate operations/references are checked before
moving to another document. Impossible two-pass work policies fail before opening.

The defaults are 32 Mi work units for the complete retained request and 4,000,000
for each lifecycle projection, including the full tracks-v1 replay reservation.
The pure aggregate ceilings are 1024 frames, 4096 original objects, 1024 operations,
4096 operation endpoints and 4 MiB canonical output. All rows participate; no
successful truncated report is returned.

The existing deployment must already exist. Its normal exclusive publisher open
may perform recovery housekeeping, which remains outside indexed source-read
counters. The query neither initializes a deployment nor reconciles pending
external effects. The original final admission callback precedes durable-head and
effect-store verification; no extension callback follows those final checks.

### Validation scope

The actual production-source lineage/JSON target passed **32 tests**: 28 new
projector/renderer cases and four embedded wire tests. It used the pinned compiler,
the genuine current dependency-free fss-core library, and the actual production
wire parser, tracklet projector, lineage projector and JSON renderer. Tests cover
unchanged tracklets, source alignment, forged reports, normative self endpoints,
all cancellation cuts, exact work/output limits, deletion/reuse, unsupported
references, barriers, privacy and writer refusal.

Fourteen additional real retained-owner contracts are authored for XML/RTP custody,
frozen-v1 non-upgrade, empty/rejected sources, cumulative two-pass limits, source
tampering/deletion, cancellation, final authority checks and no effect reconciliation.
Those native contracts are **not executed**. Genuine Asupersync compilation was
previously killed before FSS diagnostics; the execution environment subsequently
went offline. This checkpoint is not native integration or release qualification.
After execution recovered, all lifecycle sources passed pinned rustfmt and
whitespace checks, and the actual-source lineage target was rebuilt and passed
32/32 again. Native custody and full CLI tests remain unexecuted.

```sh
cargo test --locked --offline -j1 -p fss-core --test onvif_lifecycle_contract
cargo test --locked --offline -j1 -p fss-reference --test onvif_metadata_lifecycle_custody
```

The subsequent zone integration also checked the complete recursive metadata CLI
module tree and corrected explicit child paths for tracks/lifecycle/report modules.
Those pinned parse/module-resolution checks pass; native typechecking remains
separate. See [source-verified vendor zones](onvif-vendor-zones.md) for the independent
geometry query and exact original-occurrence correlation.
