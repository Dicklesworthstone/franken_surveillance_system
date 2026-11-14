# Approved event metadata in webhook alerts

The existing native webhook can now carry useful event context under an explicit
`event-metadata-v1` disclosure profile. `references-v1` remains the default and keeps
its exact existing route digest and HTTP request bytes. Both profiles use the same
plaintext relay transport, live authority checks, durable operation, bounded single
attempt, retained wire evidence and recovery path described in
[native alert dispatch](NATIVE_ALERT_WEBHOOK.md).

## Select what the relay may receive

| Profile | Content | Required route approvals |
|---|---|---|
| `references-v1` | Existing fixed text plus opaque operation, request, precondition, event-root and event-revision digests | Existing plaintext-route approval; metadata approval must be absent |
| `event-metadata-v1` | The same reference fields plus the exact declared event metadata below | Plaintext-route approval and a separate nonzero SHA-256 metadata-disclosure approval |

Unknown profiles, a missing rich-profile approval, a zero/non-SHA-256 metadata
approval, or a metadata approval attached to the reference profile refuse. There
is no implicit fallback and no ignored approval field. An approval handle is
evidence for the existing live capability owner; supplying a digest grants no
authority by itself.

The rich route binds the numeric peer, path, plaintext approval, profile and
metadata approval under `fss.http_webhook_event_metadata_route.v1`. Its channel
then participates in the existing request and precondition checks. Changing the
profile or either approval changes the route and deterministic operation,
idempotency and obligation identities. The exact route also binds the plan
approval and prepared dispatch approval. An approval obtained for reference-only
content cannot authorize event metadata.

The caller must approve that disclosure separately from transport. The relay
still receives plaintext. This feature adds no TLS, recipient authentication,
credential lookup, DNS, email/SMS provider or automatic account configuration.

## Exact contents and limits

The rich JSON body has schema `fss.webhook_event_metadata.v1`, defined in
[the schema](../schemas/webhook_event_metadata.v1.json). Its `event` object contains:

| Fields | Meaning and limits |
|---|---|
| `id`, `revision`, `kind`, `lifecycle` | The named canonical event revision and its native declared classification/state |
| `declared_interval_ns` | Earliest/latest declared event timestamps as signed decimal strings, preserving exact nanoseconds even beyond JavaScript integer precision |
| `zone_ids` | Every declared zone identifier, without inventing a location or dropping entries to fit |
| `uncertainty_reason` | The revision's complete declared uncertainty reason or `null` |
| `declared_probability` | Declared lower/upper bounds, optional algorithm-tagged calibration generation and an explicit uncalibrated/generation-declared claim; the encoder does not reverify calibration |
| `evidence_counts` | Native supporting, contradicting and neutral edge counts, plus the number of distinct supporting failure domains; their identities and payloads are not exported |
| `sensor_health` | `current: "unknown"`, basis `this_revision_only`, and separate counts of tamper reports and integrity-restoration edges in this revision |
| `decision_fingerprint`, `policy_generation`, `decision_abstained` | The retained decision metadata; digest algorithm tags are preserved, including valid Blake3 declarations |
| `physical_truth_claim` | Always `not_claimed`; canonical validity does not establish physical-event truth |

Tamper and restoration edges remain neutral evidence unless the native event
semantics explicitly classify them otherwise. Their counts do not imply current
health, repair, camera freshness or successful observation. Absence of such edges
does not become a healthy-sensor claim. The dispatch path still independently
applies its existing lineage, cross-event tamper and
[retained source-health](ALERT_SOURCE_HEALTH.md) gates.

The encoder accepts only the exact canonical EventHypothesis bytes named by the
plan: it checks the SHA-256 pin, canonical domain/schema, complete decoder
consumption, native event validity and canonical revision digest. An independent
128 KiB input limit precedes decode; native event string/count limits also apply.
No free-form model summary, track identifiers, raw video, evidence payloads,
failure-domain names, model receipts or decision-reason prose is added.

The **complete HTTP request**, including headers, numeric Host, path, idempotency
key, Content-Length and escaped JSON, must fit the unchanged **4096-byte** allowance.
The encoder refuses the whole request on overflow. It never drops zones,
counterevidence or uncertainty and never truncates a field. Quotes, backslashes,
control characters and Unicode line separators are escaped as JSON data; hostile
zone or uncertainty text cannot inject an HTTP header or another JSON field.

Both CLI planning paths run that exact encoder before durable effect preparation,
and report its SHA-256 and byte count. The native attempt repeats encoding before
commitment. A preview is a representation check, not permission to send: current
event, policy, source health, session/case witnesses and effect authority are
revalidated through the existing owner before and during dispatch.

## CLI and MCP selection

Choose the profile when creating the route. For the event CLI, add the two rich
options to the existing preview command:

```sh
fss-event alert --root /path/to/deployment --site site:home \
  --event-id event:example --relay 127.0.0.1:8080 --path /alerts \
  --plaintext-approval "$PLAINTEXT_APPROVAL" --deadline-ms 5000 \
  --disclosure-profile event-metadata-v1 --metadata-approval "$METADATA_APPROVAL"
```

The approval variables must contain independently supplied `sha256:<64 hex>`
handles for the intended relay and metadata disclosure. This command previews the
plan. Its report names `disclosure_profile`, `metadata_approval`,
`request_preview_sha256` and `request_preview_bytes`. The returned next command
preserves both profile options. Follow the existing separate exact plan-approval
and dispatch-approval steps; a preview sends nothing.

The canonical agent CLI uses the same selection:

```sh
fss plan --json --root /path/to/deployment --session session:example \
  --intent alert --event-id event:example --relay 127.0.0.1:8080 --path /alerts \
  --plaintext-approval "$PLAINTEXT_APPROVAL" --deadline-ms 5000 \
  --disclosure-profile event-metadata-v1 --metadata-approval "$METADATA_APPROVAL"
```

The returned response and rich ControlPlan identify the disclosure, separate
approval, complete request hash and size. Repeating the exact plan with its
returned `--approve` value durably prepares it. `fss commit` continues to accept
the retained plan ID and exact dispatch approval; it reconstructs the profile
from that retained plan instead of accepting a mutable disclosure override.

MCP's existing `plan` tool accepts the same literal arguments as
`disclosure_profile` and `metadata_approval`. The tool schema requires the approval
only with `event-metadata-v1`, and the command maps through the same strict native
CLI parser. MCP's fixed deployment/principal scope and existing `commit` tool are
unchanged. A model cannot invent an approval or widen a previously approved plan.

## Durable compatibility and recovery

Reference-only `PlanRecord` values retain the exact `fss.reference_agent_plan.v1`
encoding, including historical records and identity. Rich routes use
`fss.reference_agent_plan.v2`, retaining the selected profile and approval after
the existing route deadline. V2 refuses an absent or invalid metadata approval
and does not admit a second encoding of reference-only v1. Publication validates
the disclosure choice before filesystem mutation. Backup descriptions show the
profile and approval from the retained record.

The same complete encoded request is handed to the transport and retained in the
existing wire observation. Rich content therefore has the same approved local
wire-custody footprint as the bytes sent to the relay. Default inspection reports
show digests and byte counts, not raw request/response text. A full 2xx response
still means relay acceptance only; it does not close the delivery obligation.
Lost acknowledgement, interruption, process restart and storage recovery never
authorize a resend. Exact identity retries preserve the existing durable state.

## Validation evidence

Native tests of the actual production core-only modules cover nine disclosure
cases, four identity/approval cases and nine durable-plan cases. They freeze the
legacy route, complete 741-byte HTTP request, operation/plan/dispatch digests and
452-byte v1 plan record. Other cases cover tagged digests, complete output at the
4096-byte boundary and one byte beyond it, hostile text, canonical corruption,
strict rich approval/record decoding, profile-bound identities and an
indeterminate operation that cannot be restored to Prepared by retry.

The existing native loopback tests now exercise **both profiles** for exact
request/preview identity, durable-before-connect ordering, acceptance without
delivery proof, lost acknowledgements across restart without resend, and authority
changes before the first write. Two additional native owner tests refuse an
attempted reference-to-metadata upgrade and forged canonical revision before
commitment or connection. Focused event-CLI and MCP tests cover paired options,
strict refusals and visible preview/next-command selection.

Those workspace integration suites are authored and source-reviewed but **have not
run in this session**: the full dependency build was previously killed while
compiling Asupersync. The passing core-only tests compile real production files
and the real `fss-core`; they do not substitute mocks for those dependencies and
do not claim full runtime or provider qualification. Focused workspace commands:

```sh
cargo test -p fss-reference --lib alert::webhook --locked --offline
cargo test -p fss-cli --lib alert_effect::identity --locked --offline
cargo test -p fss-cli --bin fss-event alert::tests --locked --offline
cargo test -p fss-cli --bin fss-mcp control::tests --locked --offline
```
