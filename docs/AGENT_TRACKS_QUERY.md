# Retained detector track queries

`fss query --target tracks` exposes the existing native Kalman/IoU track analysis
through AOP-005 in the CLI and MCP. It reads one exact retained package-detection
report and reconstructs the selected label with an explicit tracking recipe. It
performs no new inference or publication and can coexist with a deployment writer.

```sh
fss query --target tracks --json \
  --root /absolute/path/to/deployment \
  --report-digest sha256:RETAINED_DETECTION_REPORT \
  --label person --verify-tracks-source=yes \
  --confirmation-hits 2 --maximum-missed-frames 1 --minimum-iou-ppm 100000 \
  --max-entries 16
```

The digest is the original retained detector report identity, not its canonical
detection-record payload digest. The label must exactly match the retained model
vocabulary. The recipe values shown are the CLI defaults, matching `fss-event`.
Use [report discovery](AGENT_REPORT_CATALOG.md) to find that handle with
`fss query --target reports --family package_detection_record`.

The immutable source owner verifies original encoded evidence internally. This
requires a separate source-read grant; original media and model bytes are never
returned. For MCP, the operator supplies that grant when launching the server:

```sh
fss-mcp --root /absolute/path/to/deployment \
  --principal principal:operator --allow-tracks-source-verification
```

After MCP initialization, use the existing `query` tool:

```json
{
  "target": "tracks",
  "report_digest": "sha256:RETAINED_DETECTION_REPORT",
  "label": "person",
  "max_entries": 16
}
```

The client cannot change the fixed root or principal, supply a loose file, enable
source verification, or acquire a grant from QSR/recorder permissions. The native
`AgentResponseEnvelope` and protected `AgentCognitiveEnvelope` pass through unchanged.

## Observations and continuations

Each `claim:tracks:observation:<sequence>` proposition carries one complete JSON
row after its descriptive prefix. Rows retain the native track identity, matched
source frame, assigned detection and uncalibrated score bits, filtered box,
per-sample confirmation state, continuity epoch and exact source/model proof pins.
Each page also carries all source-frame metadata and native continuity boundaries.
Protected deployment knowledge, contradictions and unresolved obligations remain
in the response.

An earlier tentative observation stays tentative when its track later confirms.
Missed frames and predicted-only positions are not fabricated as observations.
Track identity is local to this analysis; it does not establish physical identity,
detector accuracy, continuous coverage or absence. Capture bounds retain their
declared source clock basis without a UTC conversion.

Return the exact response continuation as `--continuation` or the MCP
`continuation` field. Page size is 1–32. Every page binds the full current authority
and effect prefix, report, label, recipe, principal and read limits. Changing any
of those inputs refuses the old cursor. Optional `--anchor` / `anchor` pins the
current deployment token independently of the historical source report.

The default cumulative allowance is 1 GiB of successful payload reads and
1,000,000 payload-read attempts, including history and final revalidation. It may
be changed with `--max-query-read-bytes` and `--max-query-read-objects`, up to
4 GiB and 4,000,000 attempts. MCP uses canonical decimal strings for these limits;
recipe values and page size use JSON integers. These are not filesystem syscall
counts. The 60-second deadline is cooperative; CPU time and output tokens are not
metered. A complete protected response over 256 KiB refuses without a partial row.

This is a reference implementation. Read verification consists of bounded
observations with live permission checks; it does not lock the filesystem or
provide an atomic snapshot or read lease.
