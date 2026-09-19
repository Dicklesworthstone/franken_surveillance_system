# Executable investigation reference (FSS-213 / FSS-214 / FSS-215)

`fss_reference::agent_session::checkpoint::journal::coordination::investigations` composes the
existing `InvestigationState` record and `InvestigationCaseState` disposition machine. It is not
a new public fss/1 operation: the eventual transport owner must project it through AOP-006.

`ReferenceInvestigationStore::execute` accepts a live session, authenticated principal and trusted
runtime clock. It rechecks `CAP-AGENT-INVESTIGATE-001`, mission, privacy, anchor and ContractBasis.
The entire input case and each citation must already be authorized by its evidence owner. A
privacy-class string is not a per-object authorization proof. No probe, model, effect or network
operation executes here.

## Immutable case progression

Open accepts revision one in Draft at the session's exact basis with a future decision deadline.
An exact opening retry returns the current revision (even a terminal one) without resetting it.
Different opening parameters cannot reuse an identity. All historical revisions remain available
to authorized readers; they are not permission to overwrite the current head.

Change uses the full revision digest as a compare-and-swap precondition. A second authorized
session of the same principal and mission may continue the case, but a stale writer cannot erase
newer work. Each revision binds its author session, principal, privacy class, predecessor,
runtime timestamp, optional assessment root, public record and orthogonal disposition state.

The reference deliberately offers no arbitrary replacement-record method. Citations append to
support or contradiction lists. Hypotheses, predictions, unknowns, knowns, discriminators, probe
handles, stop rules and the exact basis remain preserved. Additional hypotheses, revised
questions, knowledge-state refinement and world-drift rebase need separate witnessed contracts;
this implementation refuses to simulate them by overwriting the original case.

Assess requires an attached support citation for Supported and an attached contradiction for
Disfavored/Refuted. The existing core transition table remains authoritative: refutation is final
and an advanced hypothesis cannot silently return to Live. Assessment does not promote a
statement's knowledge state, verify source custody, collapse a WorldEnvelope, or create effect
authority. These are recorded, attributed cognition decisions, not physical truth claims.

Conclusion requires the exact declared stop rule, an assessment digest, acknowledgement of every
retained unknown ID, and no Live alternatives. Resolved also requires a Supported hypothesis;
Refuted requires every hypothesis Refuted. Unknowns and alternatives remain in the result.
Closure is permitted only after resolution, refutation, cancellation or explicit indeterminacy.
Closing an indeterminate case archives uncertainty; it does not establish a conclusive answer.

At the decision deadline, the owner may record indeterminacy, cancellation or closure, but cannot
continue assessment or fabricate a conclusive answer. No background timer exists in this
synchronous oracle: read results retain the deadline and original state; deadline enforcement
occurs at each attempted mutation. Case cancellation never cancels or settles external work.

## Bounds and remaining integration

Case, revision and retained-canonical-byte ceilings include terminal history. Fixed schema limits
cover every nested prediction, evidence, contradiction, statement, discriminator and handle
before retained-state allocation. Duplicate statement/discriminator identities and mismatched
expected-outcome/separated-hypothesis counts are refused. No history is evicted to admit work.

`ReferenceInvestigationStore` is the in-memory oracle. A failed operation can advance
session/store clocks or expire a session even though no case revision was appended. The durable
integration below commits those changes before returning. Replacing an existing store with an
empty one is not recovery.

The focused command is:

```sh
cargo test -p fss-reference coordination::investigations
```

Tests were added for lifecycle, stale writes, authority narrowing, cross-domain non-disclosure,
residual retention, final refutation, deadline boundaries, capacity and byte-exact deterministic
execution. Rust compilation/tests/fmt/clippy were unavailable in the editing environment. Source
checks and Git blob verification do not establish qualification. Deployment-wide canonical
publication, public request/response envelope dispatch, source-custody admission, full resource
accounting and GATE-115 remain open.


## Durable investigations in the session/work journal

The existing `DurableSessionStore` now provides `enable_investigations(InvestigationLimits)` and
`investigate(principal, session, command, now)`. The trusted owner first enables coordination;
case initialization is a one-way, committed transition with immutable bounds. Exact retries
preserve existing cases and different limits or repeated initialization records are rejected.

The store stages sessions, work claims and cases as one candidate. The command and exact
before/after session checkpoint witnesses are committed before returning a case revision or
semantic refusal. An uncertain append fences all three APIs until the existing pending-append
reconciliation resolves the exact write. Reconciliation does not redeliver the withheld response.
A failed capacity preflight cannot acknowledge a case update, discard history, or clear a fence.
Ordinary session checkpoint and work-claim records preserve the case state while interleaving
through the same journal; their bytes and interpretation are unchanged.

The private coordination-command record family (`0x5743`) now admits explicitly versioned case
payloads in addition to its existing work payload. This is not a changed interpretation of old
work bytes:

| Payload domain | Contents |
|---|---|
| `fss.reference_investigation_init.v1` | Case/revision/retained-byte ceilings and current session checkpoint witness |
| `fss.reference_investigation_record.v1` | Exact request bytes, before/after session witnesses, and outcome digest |
| `fss.reference_investigation_request.v1` | Principal, session, runtime instant and the typed case command |

The case request uses handwritten canonical bytes with explicit tags, lengths, big-endian
integers and algorithm-qualified digests. Every nested count and string is bounded before its
allocation; the complete request and record have a 1 MiB ceiling. Unknown versions/tags,
noncanonical booleans, duplicate or unsorted residual acknowledgements, trailing bytes and
truncation fail closed. The existing core case record remains the public payload; this private
journal layout does not introduce a transport-local `fss/1` verb or public schema.

Recovery re-executes the case engine under its historical session authority. It verifies the
exact success-revision or refusal digest and both session checkpoint witnesses, instead of
accepting a serialized lifecycle, hypothesis assessment, author or revision as authoritative.
All fourteen refusal identities remain distinct without persisting unbounded error strings.
Older readers reject the unrecognized payload version instead of silently dropping cases.

Use the existing `open_existing_with_coordination`, `inspect_with_coordination`,
`reconcile_pending`, and `recover_existing_with_coordination` methods. Recovery requires an
independently trusted exact root. Cold recovery verifies semantic replay before any explicit
incomplete-tail truncation; a complete case change with a lost acknowledgement cannot be
removed merely to match an older root. Session revocation and expiry remain effective after
restart, and a new authorized session can continue the exact case without replacing its history.

Case limits are bounded by the reference's absolute ceilings, persisted at initialization and
recovered unchanged. This extension does not introduce a per-open case-limit migration or
compaction mechanism. The journal and containing directory still require a protected exclusive
owner. Checksums alone do not authenticate a root, resist rollback, or establish multi-process
mutual exclusion. Source roots remain citations, not custody proofs; no probe or effect executes.

The twelve added journal tests cover interleaved session/work/case histories, new-session resume,
expiry refusals, all four append cut points, hot/cold recovery, stale roots, rehashed false outcomes
before a torn tail, reset attempts, capacity, every truncated request prefix, all lifecycle and
knowledge-state tags, and malformed counts/acknowledgements. Together with the initial twelve
engine tests this provides 24 focused regression tests. They are committed source, not executed
qualification evidence: Rust build/test/fmt/clippy remain unrun in this editing environment.
