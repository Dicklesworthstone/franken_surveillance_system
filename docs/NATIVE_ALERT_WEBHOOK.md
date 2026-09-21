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

## Explicit live authority

Implement `WebhookAuthority` using the owning Cx or equivalent capability owner.
There is no permissive implementation in production code. Every check receives
`WebhookScope`: the frozen endpoint, actual durable OperationReceipt (including
principal, capability, lease and current state), and local effect-journal path.
The owner must verify these against current authorization, disclosure policy,
resource limits, cancellation and an independent live deadline clock. It also
owns authorization for the canonical-authority and verified object reads supplied
to this API. A caller-provided admission timestamp is not a post-syscall clock.

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
failure-domain tamper state. Missing/unreadable authority refuses; the module does
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
remaining lease and five seconds; all later operations are nonblocking.

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
| Owner lost before recording | Committed remains durable | Still unresolved |

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

`WebhookEvidence::encoded()` is the complete bounded evidence object to retain
through an existing authorized custody owner. The effect journal stores its digest,
not those full wire bytes. The application must persist them separately before
releasing this owner when future wire-level hydration is required. This slice
adds no second journal, automatic evidence checkpoint, terminal-proof verifier, or
canonical-publication shortcut. Never feed its local hash to the in-memory
provider oracle as invented independent delivery proof.

HTTP semantics/framing references: RFC 9110 section 15.3.3 (202 is acceptance,
not completed processing) and RFC 9112 sections 2, 4, 5 and 6.3. The supported
reader profile is intentionally narrower than the complete HTTP specifications.

## Validation status

Sixteen Rust contracts were authored. They cover native loopback POSTs under
1/7/4096-byte operation limits, durable-before-connect ordering, restart/no-resend,
acknowledgement versus delivery, route/request forgery, cross-history receipt
refusal, current-ledger invalidation between commit and send, post-write revocation,
local recording refusal, every early socket allowance, response corruption/limits,
and response-head fragment boundaries. Event fixtures are synthetic and labelled
as such; they test authorization plumbing, not real-camera detection quality.

The Rust tests, compilation, rustfmt, Clippy and controlled native qualification
have NOT run in this sandbox: cargo/rustc are unavailable. The bundle's Python/h11
checks exercise independent wire fixtures and a transcribed response profile, not
the Rust sender. No real operator notification, remote provider account, TLS,
physical camera, human delivery or production qualification was exercised.
