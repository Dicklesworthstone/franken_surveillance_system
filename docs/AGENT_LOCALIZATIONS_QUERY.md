# Discover retained camera-localization results

`fss query --target localizations` finds retained recorded-localization packages
without requiring their identities in advance. It uses the existing AOP-005
query operation and returns the same protected CLI/MCP cognitive envelope as
other native queries. The deployment must already exist.

```sh
fss query --target localizations --json \
  --root /absolute/path/to/deployment --max-entries 16

fss query --target localizations --json \
  --root /absolute/path/to/deployment \
  --sensor sensor:rear --stream stream:rear:1
```

An initialized MCP server uses its launcher-fixed root and principal:

```json
{
  "target": "localizations",
  "sensor": "sensor:rear",
  "max_entries": 16,
  "max_query_results": "1024"
}
```

The native owner is
`fss_reference::agent_localizations::query_localizations`. CLI and MCP share its
request, complete-index verification, continuation and output projection. The
closed selector schema is
[`agent_localizations_query.v1.json`](../schemas/agent_localizations_query.v1.json).

## What is discovered

The index contains actual completed `recorded-localization-<identity>` native
publications produced by `fss-file localize --retain-result yes`. Their ledger
records remain authority `local_root_reachability` records; discovery does not
relabel them as detector or zone-report cognition declarations.

Each `Retained localization metadata: ` proposition contains one complete JSON
row in canonical package-identity order. It preserves:

- The package identity, exact publication slot/root, receipt digest and commit sequence.
- The completed source import, import root, manifest, original source anchor and capsule.
- The sensor, stream, declared capture interval, codec, selected segment and replay range.
- The current privacy binding and original immutable mask-policy identity when present.
- Original twin, scene, atlas, atlas-provenance and descriptor-generation pins.

The package, receipt, publication root and capsule have exact H0 metadata handles
using their existing native formats. These handles confer no source-media,
perception, calibration-adoption or effect authority. Large integer values and
capture nanoseconds are decimal strings so their complete precision survives JSON.

Every retained native outcome is discoverable: pose candidates, insufficient
matches and bounded geometric failure. Discovery checks the canonical recipe,
receipt source header and frozen parameters; it does not interpret candidate
geometry or independently reproduce the computation. Every row explicitly says:

| Field | Meaning |
|---|---|
| `verification: metadata_only` | Metadata and current native custody/privacy bindings were checked. |
| `replay: not_performed` | No source decoding or localization computation was executed. |
| `candidate_outcome: not_interpreted` | Discovery does not turn the opaque receipt result into a pose claim. |
| `activation_performed: false` | This read does not adopt calibration or change authority. |
| `adoption`, `current_calibration`, `physical_coverage`: `unknown` | Historical candidate custody does not establish current physical position or coverage. |
| `source_payload_availability`, `archive_payload_availability`: `unknown` | The reader does not open original media, cached pixels, twin or atlas payloads. |

The complete protected deployment context, historical health, coverage
uncertainty, contradictions and unresolved obligations remain visible regardless
of filters or page size. Valid committed localization retractions are counted
without exposing retracted metadata. An empty successful page is a bounded
metadata result, never evidence of physical absence.

## Exact selection and continuation

All optional selectors are conjunctive and apply only after verification of the
complete bounded index:

| CLI | MCP | Exact identity |
|---|---|---|
| `--sensor` | `sensor` | Native source sensor, at most 128 portable identifier characters. |
| `--stream` | `stream` | Native source stream, at most 128 portable identifier characters. |
| `--import-id` | `import_id` | Nonzero canonical SHA-256 completed import identity. |
| `--twin-digest` | `twin_digest` | Nonzero canonical SHA-256 original twin archive identity. |

Use the response's exact native continuation for the next page. It binds the
whole verified index, protected diagnostic boundaries, full authority/effect
prefix, principal, predicates, page size and every read/snapshot limit. A changed
scope or head requires a new query; the reader does not silently rebase a cursor.
`--anchor` / `anchor` optionally supplies the exact current deployment token.
Historical `at`, raw offsets, paths, source verification and execution selectors
are rejected.

## Bounds and failure behavior

| Control | Default and hard maximum |
|---|---:|
| `--max-entries` / `max_entries` | Default 16; 1 through 32 package rows per page. |
| `--max-query-results` / `max_query_results` | 1024 packages in the complete index, before filters. |
| `--max-query-read-bytes` / `max_query_read_bytes` | 268435456 metadata payload bytes, including final rereads. |
| `--max-query-read-objects` / `max_query_read_objects` | 65536 payload-read attempts, including final rereads. |
| Complete ledger traversal | 65536 objects and batches. |
| Complete protected response | 256 KiB; oversized output refuses without a prefix. |
| Cooperative deadline | 60 seconds across query and rendering. |

MCP `max_entries` is an integer. The three allowance values are canonical decimal
**strings**. The native owner also binds and checks its immutable snapshot
ceilings. A small page or an empty filter cannot bypass complete-index work.

One nonrenewing allowance covers opening history, source metadata, recipes,
receipts, publication manifests and final metadata/payload/publication/head
checks. Missing original media or archive bytes can leave discovery successful;
explicit deletion or tombstone restrictions are still enforced. Damaged excluded
metadata, changed privacy, authority drift, exhausted budgets, cancellation and
incomplete publication refuse the complete query. A refusal is not a successful
empty match set.

The read can coexist with the active publisher. It never initializes the root,
locks a publisher, recovers journals, repairs objects, writes a session or
publishes a new result. Revalidation is a bounded sequence of observations, not
an atomic filesystem snapshot or a read lease. CPU, output tokens and physical
filesystem syscall counts are not represented as measured costs.

## Inspect or reproduce a selected result

Use `package_identity`, `publication_root` and `receipt_digest` as the three exact
pins for the existing `fss-file read-localization` or `verify-localization`
commands. Full inspection separately requires receipt and twin/atlas byte
custody and now also uses an immutable owner while ingest remains active. Its
complete status and create-only receipt export follow final revalidation under
one byte/read allowance. Explicit native verification additionally decodes
retained source media and reconstructs the candidate receipt; discovery grants
neither operation.
See [retained localization and replay](retained_localization.md).

The genuine-producer native and real-process CLI/MCP tests are
`agent_localizations_contract` and `localizations_query_cli_contract`. They cover
all native outcomes, active writers, exact paging and scope, missing assets,
current privacy/tombstones, excluded corruption, cancellation and final drift.
Focused hosted execution is supplementary; release authority remains the
repository-owned qualification workflow and retained DSR receipts.
