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

This initial slice is an in-memory reference. A failed operation can advance session/store clocks
or expire a session even though no case revision was appended; durable owners must commit those
changes before returning. Replacing an existing store with an empty one is not recovery.

The focused command is:

```sh
cargo test -p fss-reference coordination::investigations
```

Tests were added for lifecycle, stale writes, authority narrowing, cross-domain non-disclosure,
residual retention, final refutation, deadline boundaries, capacity and byte-exact deterministic
execution. Rust compilation/tests/fmt/clippy were unavailable in the editing environment. Source
checks and Git blob verification do not establish qualification. Persistent integration, public
request/response envelope dispatch, source-custody admission and GATE-115 remain open.
