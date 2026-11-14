# Discover retained model, detector and zone reports

`fss query --target reports` finds exact report handles in an existing deployment.
It reads retained metadata without original media, model execution, publisher
locks, recovery or writes. Use it before selecting a report for a tracks or QSR
query, or before inspecting a native scalar-model run; no source-verification
grant is needed for discovery.

```sh
fss query --target reports --json \
  --root /absolute/path/to/deployment --max-entries 16

fss query --target reports --json \
  --root /absolute/path/to/deployment \
  --family package_detection_record
```

Supported families are `package_detection_record`, `package_zone_report` and
`model_invocation_receipt`.
Optional `--from-ns` and `--through-ns` select closed overlap with the declaration's
source-native validity interval. They do not align clocks or convert to UTC.

For an initialized MCP server with its operator-bound root and principal, call
the existing `query` tool:

```json
{
  "target": "reports",
  "family": "package_detection_record",
  "max_entries": 16
}
```

Each report proposition contains a complete JSON metadata row after
`Retained report metadata: `. For package reports, `report_digest` is the handle
to pass to the corresponding native reader. For detector reports it is distinct from
`record_digest`, the canonical detection-record payload. Rows also preserve the
publication root and slot, native schema, declared interval and commit sequence.
Zone schemas preserve the v1/v2 distinction, but discovery does not certify QSR
eligibility. H0-only evidence handles cite verified metadata; they grant no media
hydration or `ReadMedia` permission.

## Native scalar-model runs

Completed `fss-infer run` results are discoverable without having saved the
original terminal output:

```sh
fss query --target reports --json \
  --root /absolute/path/to/deployment \
  --family model_invocation_receipt
```

This family selector covers the native `RecordedInference` receipt format and
model-run declaration namespace. Generic executor-activity invocation receipts
use a different format and remain outside this catalog. Malformed declarations
claiming the native model-run namespace refuse the query.

MCP uses the same `query` target and family. For this family, `report_digest` and
`record_digest` both identify the actual retained execution-receipt object. The
typed `model_run` block gives the separate native `run_identity`, original
`executor_profile_digest`, `model_digest`, `frame_root`, `import_identity`,
`segment_index` and `interpretation`. The semantic run identity is a lookup key;
it is never advertised as an available blob or an evidence-hydration handle.
The source interval and completion commit retain their original meaning.

Use the block's exact selectors with the [inference reader](INFERENCE_OPERATOR_WORKFLOW.md):

```sh
fss-infer read --root /absolute/path/to/deployment --site SITE \
  --import-id IMPORT_ID --segment SEGMENT --interpretation INTERPRETATION \
  --run-id RUN_ID
```

Replace the four uppercase selectors with the values in `model_run`; `SITE`
must match the deployment's site lineage. The inference reader independently
checks current source, privacy, model and tensor custody. Its `replay` operation
also requires the original executor profile to match the current implementation.
Discovery itself reads no original media, decoded pixels, model bytes, normalized
input or output tensors and performs no model execution. It verifies the native
receipt and publication, exact decoded-frame completion, original import/capsule
metadata and current deletion restrictions. Historical profiles remain visible.

Model rows explicitly report `tensor_payload_verification=not_performed` and
`model_execution=not_performed`, alongside the existing unknown source-payload
availability and `source_reconstruction=not_performed`. They make no package-zone
or QSR eligibility claim. Missing or corrupt payload bytes can therefore leave
intact metadata discoverable while later inference inspection refuses; tombstones,
committed source deletion and damaged selected metadata refuse discovery.

## Complete metadata, bounded disclosure

All supported report declarations are verified before filters or pagination.
Corrupt metadata outside the selected family therefore refuses the whole query.
Original source media is not read: metadata can remain discoverable when later
source reconstruction would refuse. Source availability, coordinate privacy
eligibility, physical identity, coverage and absence remain unestablished.

Return the exact continuation in `--continuation` or MCP `continuation`. Every
page binds the principal, filters, page size, complete verified index, all read
limits and current authority/effect prefix. Changing those inputs invalidates the
cursor. Optional `--anchor` / `anchor` pins the current deployment token.

The default and maximum complete index is 4,096 supported reports, reduced by
`--max-query-results`. Its bound applies before filters. One cumulative allowance
of at most 256 MiB and 65,536 payload-read attempts covers history, report metadata
and final revalidation. Lower it with `--max-query-read-bytes` and
`--max-query-read-objects`. MCP uses canonical decimal strings for times and these
three limits; `max_entries` is a JSON integer from 1 to 32. The 60-second deadline
is cooperative. The complete protected response must fit 256 KiB or it refuses.

Use a discovered detector handle with [the track query](AGENT_TRACKS_QUERY.md),
or a screened zone-report handle with [the QSR query](QSR_OBSERVATIONS.md).
Both source-verified readers require their own separate explicit grant and can
refuse a handle that discovery successfully returned.
