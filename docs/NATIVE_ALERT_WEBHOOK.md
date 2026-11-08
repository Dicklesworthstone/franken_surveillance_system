# Native HTTP alert relay dispatch

`fss_reference::webhook` sends a real, bounded HTTP POST for an existing prepared
alert plan. It uses the existing canonical event eligibility, lineage/tamper,
idempotency and durable effect journal. It is not an in-memory provider oracle.
No model output can call a public unguarded socket-send entry point in this module.

This is an explicitly approved **plaintext relay** profile. It is not HTTPS,
authenticated provider identity, email/SMS/push integration, or an automatic
notification-service account connection. There is no downgrade, DNS resolution,
redirect, credential handling, runtime dependency, or detached worker. Do not use
this profile where transport authentication or confidentiality is required.

## Bind the route before preparation

Construct `WebhookEndpoint::new(peer, target, plaintext_approval)` from an exact
owner-resolved `SocketAddr`, a non-secret absolute path, and the independently
issued approval digest. Query strings, percent escapes, fragments, userinfo and
path traversal segments are refused. The Host header is the exact numeric peer,
not a separately mutable virtual-host mapping. Address/path details are omitted
from Debug output, but remain explicitly inspectable by their authorized owner.

Use `endpoint.channel()` as the existing `PrepareAlertParams.channel` when calling
`DurableEffectJournal::prepare_alert`. Do not modify an already-prepared plan to
point somewhere else. The channel pins peer, path and plaintext approval. The
existing request digest binds that channel and the exact canonical event revision.
An approval digest is only a handle; it does not create a capability.

The POST is bounded JSON with a fixed notification text and the operation,
request, precondition, event-root and event-revision SHA-256 references. It does
not export raw video, arbitrary model prose, credentials, or an unvalidated event
summary. An Idempotency-Key header carries SHA-256 of the existing idempotency key.
The relay can use that key for deduplication, but the client does not assume the
relay supports it and never uses it as permission to retry a committed request.
A relay that needs more event detail must hydrate it through a separately
authorized evidence reader.

## Approve local wire retention with the dispatch

Both `fss-event alert` and the canonical `fss commit` path use the fixed policy
`local-root-last-exact-http-wire-v1`. The dispatch preview names that policy, and
the `fss.cli_alert_dispatch_approval.v2` digest binds it together with the exact
plan, operation, actor and deadline. Obtain a fresh approval from the current
preview: an earlier v1 dispatch approval does not authorize this additional
retained-byte footprint. Retention is part of the approved native attempt; there
is no separate flag that silently drops its wire evidence.

The retained object contains the complete bounded request, the number of bytes
accepted by socket writes, and the exact response prefix returned by the socket,
including any body suffix received with the response head. It also binds the
intent, route digest, original commitment root, admitted times, I/O count and
outcome. Response bytes can include untrusted headers or body text. Default CLI
reports and Debug output expose digests, counts and outcome metadata, not those
arbitrary bytes.

Before network commitment, the shared runtime checks the explicit retention
authority and configured capacity for two objects and one publication root. It
reserves bounded cleanup work, effect-history reads and 256 KiB of custody byte
headroom. Source validation cannot consume that reserved custody headroom. These
checks refuse known insufficient allowances or configured capacity before sending;
later operating-system storage failures still require recovery.

## Explicit live authority

Implement `WebhookAuthority` using the owning Cx or equivalent capability owner.
There is no permissive implementation in production code. Every check receives
`WebhookScope`: the frozen endpoint, actual durable OperationReceipt (including
principal, capability, lease and current state), and local effect-journal path.
The owner must verify these against current authorization, disclosure policy,
resource limits, cancellation and an independent live deadline clock. It also
owns authorization for the canonical-authority and verified object reads supplied
to this API. A caller-provided admission timestamp is not a post-syscall clock.
`checkpoint` returns the actual timestamp checked by the owner. The transport
rejects a returned time earlier than its input, or a non-record admission at or
beyond the network deadline. Commitment and local recording use the owner's
returned time.

Commit, connection, socket configuration, every write/read and every post-I/O
boundary are checked. The Record boundary is a **local cleanup** operation:
revoked networking does not automatically authorize storage, and expired network
leases need not prevent independently authorized obligation recording. No secret
is accepted or loaded by this interface.

## Durable commitment precedes networking

`WebhookAttempt::begin` borrows the plan, endpoint, canonical authority ledger and
exclusive mutable durable effect journal. It prepares bounded wire buffers, calls
the same `revalidate_alert_event_authority` helper as the existing dispatch paths,
rechecks live authority, then appends Committed durably. There is no socket I/O in
begin. Ineligible Prepared plans can be durably Cancelled by the existing helper.
A failed/uncertain append is not permission to bypass journal reconciliation.

Only the resulting opaque attempt can poll the network. Before connecting and
before **every** write, it also invokes the existing full dispatch-authority check,
including current revision, committed policy, event lineage and cross-event
failure-domain tamper state. Capsule-linked native support also passes the
[retained source-health gate](ALERT_SOURCE_HEALTH.md), including diagnostics
published after the alert was prepared. A health refusal before commitment keeps
the operation Prepared for inspection or explicit cancellation; it does not create
an event-displacement cancellation proof. Missing/unreadable authority refuses; the module does
not pretend to know that the event changed merely because validation failed.

Dropping an attempt before or after any network progress leaves the operation
Committed unless a later outcome was recorded. A reopened journal therefore
blocks a second dispatch. This is conservative even for a crash before the first
send: lack of a terminal receipt is not proof of no external effect.

## One bounded operation per poll

`poll(now_ns, owner, read_verified_payload)` performs at most one top-level socket
API call, then returns Pending or ReadyToRecord. There are no internal sleeps,
read/write retry loops, reconnections, or workers. The caller's existing runtime
owns scheduling. The single connection attempt has a timeout capped by the
remaining lease and five seconds. The remaining lease is computed from the
owner's latest admitted time **after** source validation, so slow metadata reads
cannot enlarge the connection timeout. Platform scheduling may still overrun a
requested timeout; the post-I/O owner check preserves that as an interruption.
All later operations are nonblocking.

`WebhookLimits` caps socket API attempts (including WouldBlock/Interrupted), bytes
per operation and the complete retained response prefix. It counts API attempts,
not every platform-internal syscall or elapsed CPU work. The whole network lease
is at most one minute. Caller clock reversal, budget exhaustion, cancellation,
revocation, disconnects and invalid responses all stop network progress. Exact
successful write counts and returned bytes are saved **before** post-I/O checks.

The HTTP/1.0/1.1 response-head reader requires complete CRLF framing and a final
status. It retains and skips at most eight informational heads; protocol upgrade
is refused. Its narrow ASCII profile rejects folded/invalid fields, duplicate
Content-Length, Content-Length/Transfer-Encoding conflicts, unsupported transfer
codings, illegal no-content framing and overlong prefixes. It does not parse or
wait for response-body completion. Any body suffix returned by the same read is
retained as bytes, never interpreted as human delivery proof.

## Record an observation, not a fabricated delivery proof

| Wire result | Durable effect state after explicit record | Delivery obligation |
|---|---|---|
| Complete 2xx response head | AdapterAccepted | Still Pending |
| Non-2xx response, including redirect/error | Indeterminate | Indeterminate |
| Lost acknowledgement, timeout, revocation, cancellation or malformed response | Indeterminate | Indeterminate |
| Retention or local recording fails after commitment | Last confirmed state preserved; an uncertain append requires recovery | Still unresolved |

`record(now_ns, owner)` performs only local journal work. It hashes the complete
opaque `WebhookEvidence`, including request bytes, sent prefix, received bytes,
route, admission times, outcome, and the exact journal root that committed the
attempt. The root must belong to the destination journal's verified committed
history; equal operation strings in an unrelated history are insufficient.

Exact recording retries return the same receipt after verifying committed history.
Recording failure keeps the wire evidence in the attempt and never reopens its
socket. `retire()` transfers that evidence without I/O; unfinished work becomes an
explicit Retired interruption. `record_webhook_evidence` can record transferred
evidence under newly granted cleanup authority, including after journal reopen.
Neither method transitions to Observed or Verified, synthesizes a provider nonce,
closes the terminal-proof obligation, or publishes a canonical alert outcome.

### Native dispatch retains bytes before recording the result

The shared `fss-event alert` / `fss commit` runtime performs these steps after
network progress finishes:

1. Retire the attempt and release its socket, taking ownership of the exact
   finalized `WebhookEvidence`.
2. Pass it to `retain_webhook_evidence` under explicit local cleanup authority.
   The existing object spool retains the observation and a canonical one-child
   manifest. The existing publisher commits the root last, then appends canonical
   reachability to the authority ledger.
3. Call `record_webhook_evidence` only after that custody has been verified. The
   effect journal records the observation digest and the local transport outcome.

The publication slot binds the site, operation and **original prepared-record
digest**. One preparation has one immutable wire-evidence slot. An exact retention
retry rechecks its root record, manifest, bytes and committed-history binding
without appending a second publication. A different observation, missing custody
or retracted publication refuses the retry. Later operator reconciliation may
replace the operation's latest result digest, but it cannot replace the original
wire-evidence slot.

The effect journal continues to store a digest, while the exact
`WebhookEvidence::encoded()` bytes now have their own root-last custody. The
low-level `WebhookAttempt::record` and `record_webhook_evidence` APIs do not
perform that publication themselves. Library integrations should use the same
preflight, retire, retain, then record sequence as the shared native runtime.
The [retention module](../crates/fss-reference/src/alert/webhook/retained.rs)
requires `CAP-ALERT-COMMIT-001` and explicit bounded context authority; a finite
deadline requires the original live owner admission callback.
Cold inspection returns the separate `RetainedWebhookEvidence` type. It cannot
reconstruct the opaque live evidence accepted by the recording API.

A crash before publication can leave staged bytes without admitted wire custody.
A durable root whose reachability was not committed remains an unresolved
publication and refuses custody inspection. A fully ledgered root published
before the effect result was appended remains inspectable, with
`journal_observation_recorded: false`. None of these cases authorizes another
send. Ordinary deployment recovery may classify the outstanding operation as
Indeterminate; the read-only evidence command does not perform that transition.

The immediate `AlertDispatch.retained_evidence` value is a snapshot taken during
retention, **before** the following result append. Its
`journal_observation_recorded()` getter can therefore still be false after
recording succeeds. To inspect the completed dispatch, compare
`AlertDispatch.recorded.result_digest` with the retained digest or perform a cold
evidence read. Immediate CLI reporting derives its flag from the later receipt;
the cold reader checks the verified historical journal transitions.

Local wire custody never proves human delivery. A complete 2xx head still leaves
the independent delivery obligation pending. Never feed an observation's local
hash to the in-memory provider oracle as invented independent delivery proof.

## Inspect retained wire metadata after restart

```sh
fss-alert evidence --root /path/to/deployment --site site:home \
  --operation-id operation:example
```

This command reports the original observation digest, publication slot and root,
prepared-record and commitment digests, route digest, outcome, request hash,
request/sent/response-prefix lengths, I/O count and exact admission times. It
does not print raw request or response bytes. It opens no deployment mutation
owner, acquires no deployment lock, rewrites no journal and contacts no relay.

`journal_observation_recorded` is true only when a matching local result transition
is present in verified history. It remains true after a later owner attestation
changes the latest result digest. It remains false across a crash between wire
publication and result recording. It is not provider authentication or delivery
proof. An operator attestation that cites a digest cannot create wire custody.

For an existing alert operation with no admitted published wire observation, the
report contains `wire_evidence: null`; inspect the operation with `fss-alert status`
before deciding what recovery it needs. Damaged objects, missing or mismatched
root records, retracted reachability, pending publication/deletion markers and
incomplete or corrupt journal input refuse the evidence command with no partial
JSON report. They are not reported as an ordinary absent observation.

The cold reader verifies bounded journals and the selected root, manifest,
observation and verification holds. It charges every actual metadata/read call
before I/O and rechecks observed files and absences before returning. These checks
detect observed changes; they do not claim an atomic filesystem snapshot or
perform durability resynchronization. See [operator lifecycle control](alert_lifecycle.md)
for status, cancellation and independently approved owner reconciliation.

HTTP semantics/framing references: RFC 9110 section 15.3.3 (202 is acceptance,
not completed processing) and RFC 9112 sections 2, 4, 5 and 6.3. The supported
reader profile is intentionally narrower than the complete HTTP specifications.

## Validation status

The existing webhook contracts cover native loopback POSTs under
1/7/4096-byte operation limits, durable-before-connect ordering, restart/no-resend,
acknowledgement versus delivery, route/request forgery, cross-history receipt
refusal, current-ledger invalidation between commit and send, post-write revocation,
local recording refusal, every early socket allowance, response corruption/limits,
and response-head fragment boundaries. Event fixtures are synthetic and labelled
as such; they test authorization plumbing, not real-camera detection quality.

The durable-custody change adds sixteen tests: eight
[reference recovery tests](../crates/fss-reference/src/alert_recovery_tests/webhook_evidence.rs)
and eight [CLI/cold-reader tests](../crates/fss-cli/tests/alert_lifecycle_cli/webhook_evidence.rs).
They cover exact wire retention, crash cuts, no resend, historical observation
lookup after reconciliation, metadata-only inspection without writes, corruption,
real publication tombstone names, finite physical I/O budgets and changing input.
The new tests were authored and source-reviewed; formatting and diff checks passed.
They have **not run natively**: the compiler was killed by `SIGKILL` while building
`asupersync`, before these suites could run. The separately reported 57 passing
activation tests cover different model work and do not validate this webhook path.

```sh
cargo test -p fss-reference --lib alert_recovery_tests::webhook_evidence --locked --offline
cargo test -p fss-cli --test alert_lifecycle_cli webhook_evidence --locked --offline
```

The implementation remains `implemented_not_qualified`. Source review, earlier
independent Python/h11 wire-fixture checks and unrelated test runs do not replace
native execution or controlled qualification. No real operator notification,
remote provider account, TLS, physical camera, human delivery or production
qualification was exercised by this change.
