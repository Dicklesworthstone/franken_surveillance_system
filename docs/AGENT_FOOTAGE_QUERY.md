# Canonical retained-footage metadata query

`fss query --target footage` exposes completed recorded-file imports through the
existing `fss/1` **AOP-005 query** operation and **AVIEW-003 case** response. The MCP
`query` tool selects the same implementation with `"target":"footage"`. Omitting
the target, or selecting `events`, preserves the existing event-record query.

This target finds the source segments behind retained evidence without opening a
writable deployment, acquiring its writer lock, performing recovery, or changing
an interrupted effect's state. It reads metadata only. It does not return or
verify the current availability of source-media payloads.

## Usage

```sh
fss query --target footage --json --root /srv/fss/deployment \
  --sensor sensor:loading-dock --stream stream:recording:1 \
  --max-entries 16 --principal principal:local-operator
```

Optional `--from-ns` and `--through-ns` select **inclusive overlap with the
capsule's declared capture interval**. Either endpoint may be omitted. Decimal
spelling is canonical and preserves all signed 128-bit bits. These are recorded
source coordinates: supplying a wall-clock number does not establish that a
source's estimated or monotonic interval is UTC.

```json
{
  "name": "query",
  "arguments": {
    "target": "footage",
    "sensor": "sensor:loading-dock",
    "stream": "stream:recording:1",
    "from_ns": "1000000000",
    "through_ns": "2000000000",
    "max_entries": 16
  }
}
```

The MCP deployment root and principal remain fixed by server startup. Requests
cannot override either through tool arguments. Event predicates (`event_id`,
`kind`, `state`, `zone`) and historical `at` are refused for footage. Conversely,
sensor/stream predicates are refused for the event target. Unknown or repeated
options are not silently ignored.

## Evidence returned

Each bounded result retains the completed import identity and publication root,
file manifest digest, capsule digest, sensor and stream, sequence, segment ordinal,
source byte range, whole-input digest and declared length, declared format, clock
basis, capture interval, capture-time label and gap-before flag. An `H0` evidence
handle points to the verified capsule metadata; it does not grant hydration of
the original recording. The effective privacy projection declares retained-import
and sensor-capsule metadata while keeping media payloads redacted.

The answer uses the existing `fss.agent_response_envelope.v1` with
`fss.agent_cognitive_envelope.v1`. It includes the native query plan, read-admission
receipt, complete-index selection witness, exact page digest and context decision
fingerprint. Protected deployment context—coverage uncertainty, outstanding
obligations, indeterminate effects and contradictory evidence—remains present even
when the selected page has no matching source segments.

An empty match set means that no verified metadata row in the admitted completed
import index matched the predicates. It is never a physical-absence certificate.
Uncertain or broad capture intervals remain uncertain. A declared source gap is
reported rather than filled by interpolation.

## Exact continuations and bounded work

The response's top-level `continuation` is passed back with the same target,
principal, predicates and page size. Its scope binds the full verified index and
authority/effect-history token. It cannot be moved to an event query, another
principal or different filter. Authority advancement or a changed effect prefix
requires a fresh query. `--anchor` supplies an exact current-head precondition;
there is no historical footage selector in this version.

The native owner bounds the complete index before selecting a page. Default hard
ceilings are 1,024 imports, 16,384 capsules, 65,536 ledger objects, 256 MiB of
metadata payload reads and 65,536 read attempts. A single shared allowance covers
initial history, selected metadata, and final history/custody revalidation; final
checks do not refill it. Page sizes are 1–32, with a default of 16. The complete
CLI response has a 256 KiB ceiling and is refused rather than truncated.

Metadata byte accounting excludes filesystem and syscall overhead. Context-token
metering remains distinct from unmetered full-output tokens and CPU time. CLI
reads use a cooperative 60-second checkpoint deadline; it cannot preempt a
blocking filesystem call. Cancellation discards the pending page and starts no
background work.

## Custody and limits of the implementation

Only imports completed by `ADP-FILE-001` are admitted. The owner checks committed
authority, native publication records, canonical manifests, partition membership,
capsule identity and source ranges, current deletion restrictions and local
tombstones. It revalidates metadata custody and the authority/effect prefix before
returning a page. An incomplete import, unreadable required metadata, corrupt root,
changed custody, exhausted budget or invalid continuation cannot become an empty
successful result. Full spool doctor scanning is deliberately not part of this
metadata read, so the query does not report a healthy storage root.

Optional model-receipt hydration is also excluded: a bare receipt digest is not
a type guarantee and may alias source media. Absence certification that needs
those analyses remains unknown; ordinary orientation keeps its existing behavior.

This advances the canonical footage-access part of `fss-vit-je36t.15` and
`fss-vit-je36t.8`. It does not close either broad bead. Live archive UTC candidate
lookup remains the separate `fss-archive query-utc` owner; its normal exclusive
startup/recovery semantics are not relabelled as a read-only agent query. QSR
analysis remains available through its existing retained-report owner. Continuous
recording, POS joins, trustworthy camera exposure time and physical queue/service
metrics require their own contracts and evidence.
