# Discover retained detector and zone reports

`fss query --target reports` finds exact report handles in an existing deployment.
It reads retained metadata without original media, model execution, publisher
locks, recovery or writes. Use it before selecting a report for a tracks or QSR
query; no source-verification grant is needed for discovery.

```sh
fss query --target reports --json \
  --root /absolute/path/to/deployment --max-entries 16

fss query --target reports --json \
  --root /absolute/path/to/deployment \
  --family package_detection_record
```

Supported families are `package_detection_record` and `package_zone_report`.
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
`Retained report metadata: `. `report_digest` is the handle to pass to the
corresponding native reader. For detector reports it is distinct from
`record_digest`, the canonical detection-record payload. Rows also preserve the
publication root and slot, native schema, declared interval and commit sequence.
Zone schemas preserve the v1/v2 distinction, but discovery does not certify QSR
eligibility. H0-only evidence handles cite verified metadata; they grant no media
hydration or `ReadMedia` permission.

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
