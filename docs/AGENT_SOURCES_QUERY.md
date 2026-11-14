# Discover retained source and stream history

`fss query --target sources` exposes the existing deployment's retained sensor
and stream inventory through the canonical AOP-005 query operation. It is useful
before choosing footage, a recording catalog, a report, or an event for further
inspection.

```sh
fss query --target sources --json \
  --root /absolute/path/to/deployment --max-entries 16

fss query --target sources --json \
  --root /absolute/path/to/deployment \
  --sensor sensor:rear --stream stream:rear:1
```

For an initialized MCP server with its operator-bound root and principal, use the
existing `query` tool:

```json
{
  "target": "sources",
  "sensor": "sensor:rear",
  "max_entries": 16
}
```

The native Rust owner is `fss_reference::agent_sources::query_sources`. CLI and
MCP use that same owner, request parser, continuation and response projection.
The request schema is
[`agent_sources_query.v1.json`](../schemas/agent_sources_query.v1.json).

## What the result means

Each `Retained source metadata: ` proposition contains one complete JSON row,
ordered by exact sensor identity then exact stream identity. The row preserves:

- Native sensor and stream identities.
- Retained capsule count, recorded gap count and declared source-byte total.
- Every recorded clock basis and the earliest/latest declared capture times.
- Counts of continuous and degraded historical continuity witnesses.
- The existing operational inventory's continuity classification and reason.
- At most two actual capsule-metadata handles: the first and last digest in
  canonical digest order. The row states whether those handles cover every
  capsule in the stream.

The capture interval is the hull of capsule declarations. It does not establish
continuous observation between those endpoints. Source-byte totals remain
declarations; this metadata query does not read source media. Byte totals and
capture nanoseconds are decimal strings so their exact u64/i128 values survive
JSON transports.

Continuity follows the same native rule as `fss status`. Estimated-clock file
sources remain unobservable for continuity; mixed estimated and source clocks
remain degraded. A continuous historical delivery witness never becomes a
claim about present camera health or physical coverage.

The response also includes whole-deployment counts for retained and deleted
capsules, capsules excluded by incomplete imports, completed and deleted imports,
and incomplete imports. Those counts are independent of filtering and paging.
The complete protected deployment context retains historical health findings,
coverage uncertainty, contradictions and unresolved obligations, including
evidence unrelated to the selected stream. No latest-per-sensor diagnostic
replaces older findings.

`current_health`, `physical_coverage` and `source_payload_availability` are
explicitly `unknown`. The inventory is not a configured-device directory or a
live network probe. An empty result establishes neither absence nor an offline
camera. Metadata may remain discoverable after the original media is no longer
available.

## Exact selection and bounded continuation

`--sensor` and `--stream` are optional conjunctive exact-identity filters.
They do not accept display names, URLs, partial matches, time ranges or historical
authority selectors. Identity spelling uses the existing native portable
alphabet and maximum length of 128 characters.

The default page contains up to 16 stream rows; `--max-entries` allows 1 through
32. Return the exact native `continuation` in the next request. It binds the
principal, filters, page size, every admitted limit, complete verified inventory,
protected diagnostics, and current authority/effect prefix. Optional
`--anchor` pins that current prefix. Any change requires a new query; a stale
cursor never silently rebases.

The reader verifies the complete bounded inventory before applying filters or
paging. A corrupt capsule outside the selected sensor refuses the whole query.
An inventory above a bound also refuses, even when a filter would match a small
subset.

| Allowance | Default and maximum | CLI option |
| --- | ---: | --- |
| Complete retained stream inventory | 1,024 streams | `--max-query-results` |
| Shared metadata payload bytes | 268,435,456 bytes | `--max-query-read-bytes` |
| Shared payload-read attempts | 65,536 attempts | `--max-query-read-objects` |
| Returned rows | 16 default; 32 maximum | `--max-entries` |

The native owner separately bounds ledger objects/batches, retained capsule
metadata and the initial capsule-metadata pass. The shared byte and read-attempt
allowance covers opening history, capsule metadata, protected-context rereads,
and final custody/authority verification. It is never renewed during the query.
Read attempts are not filesystem syscall counts. The 60-second deadline is
cooperative; the complete response must fit 256 KiB or it is withheld.

MCP uses canonical decimal strings for the three allowance fields and an integer
for `max_entries`. It accepts no root or principal override.

## Read boundary

Discovery requires the existing AgentQuery metadata authority. Returned H0
handles grant no ReadMedia authority, source reconstruction, inference execution,
coordinate disclosure or effects.

The reader opens existing metadata without acquiring a publisher lock, invoking
recovery, creating deployment files or repairing journals. It rehashes the
complete protected metadata and all capsule metadata it used before the final
native custody and authority observation. This is a bounded sequence of
observations, not an atomic filesystem snapshot.

Source and transport contract tests cover native projections, filtering,
continuation, unknown observability, shared allowances, unchanged deployment
bytes, corruption outside the selected page, and source-media independence.
Authored tests do not constitute release qualification; retained repository
qualification receipts remain the release authority.
