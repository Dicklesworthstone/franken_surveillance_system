# Explicit plan-outcome mission lifecycle

The native session journal can retain one explicitly enrolled **PlanOutcomeV1** execution
objective per session and original mission record. This addresses the execution-lifecycle
portion of FSS-202 / INV-087; it does not implement arbitrary natural-language success criteria.
The literal mission and objective opened with the session remain immutable and protected.
An execution result does not establish that a surveillance event occurred or that the broader
prose objective was achieved.

## Use the existing plan operation

Create a session and a normal witnessed alert plan first. Enroll that exact own-session plan:

```sh
fss plan --json --root DEPLOYMENT --session SESSION \
  --mission-bind PLAN --mission-deadline-ns DEADLINE
```

`DEADLINE` is an explicit positive absolute timestamp in signed 128-bit evidence-clock nanoseconds.
The enrollment freezes the plan identity, canonical record, root-last publication, control-plan
rendering, selected event revision, operation, obligation, principal, session, original mission
record, contract basis, baseline anchor, and decision deadline. Repeating the same enrollment
recovers the original criterion. Another plan or deadline cannot overwrite it.

Assess against the exact retained mission revision, supplied as a full SHA-256 digest:

```sh
fss plan --json --root DEPLOYMENT --session SESSION \
  --mission-assess PLAN --expected-mission sha256:REVISION
```

The first response proof pointer identifies the retained mission revision. The command accepts
no requested lifecycle state and cannot prepare, dispatch, cancel, or reconcile an effect.
Existing plan preparation, commitment, cancellation, reconciliation, and `plan --close` retain
their own approval and evidence requirements. Enrollment does not change an existing plan's
frozen preparation witness.

MCP exposes the same AOP-007 operation through `plan` intents `mission-bind` and
`mission-assess`. Its deployment and principal stay fixed by server configuration. The bind
intent takes `session`, `plan`, and `decision_deadline_ns`; use an exact decimal string if the
client cannot preserve a 128-bit JSON integer. Assessment takes `session`, `plan`, and
`expected_mission`. Mixed intents, scope overrides, arbitrary state labels, exponent notation,
and noncanonical decimal timestamps are refused.

## Derivation and terminal proofs

Enrollment records the criterion before an assessment establishes current execution facts.
Assessments derive progress from retained evidence:

- Missing preparation or stale event/generation evidence requires further evidence.
- An operation in progress remains executing.
- An indeterminate effect requires reconciliation; deadline passage cannot turn it into a
  failure, successful delivery, or cancellation.
- A terminal result requires the exact operation and obligation to agree, with the same
  nonempty proof digest, plus a matching retained execution episode and a complete, clear
  scoped closure inventory. Cancelled-before-dispatch, verified, and failed outcomes remain
  distinct. A withdrawn, never-prepared episode alone is insufficient for this profile.

The inventory includes other plans, work claims, and retained supervision owned by the session,
and cases owned by the principal in the shared mission. Missing or corrupt publication children
refuse admission. They do not count as absent work. Already-admitted source prefixes must still
belong to the current evidence/effect histories; rollback or replacement is refused.

Every assessment uses an exact expected predecessor. An exact recovered retry preserves its
immutable result rather than appending a duplicate. A stale competing write cannot replace the
head. Terminal revisions cannot be rewritten or revived by a later observation.

## Orientation, handoff, and recovery

Session orientation protects the original prose, explicit execution objective, criterion,
selected plan/event/operation/obligation, deadline, revision, and freshness statement. The
objective identity is stable across assessments; decision fingerprints bind each exact revision.
Only a current assessment supplies the capsule's typed mission state. Changes to evidence,
effect history, or the scoped closure inventory make a retained assessment historical, including
when new work appears after a terminal result. Historical terminal proof remains inspectable;
it does not assert current completion.

Handoffs carry nonempty success/failure/stop criteria for enrolled objectives, their proof
pointers, and the canonical lifecycle revision as a root-last publication child. The workspace's
original objective digest is not rewritten. Cold session-journal replay and agent backup history
retain all immutable mission revisions and their expected-predecessor commands.

Follow replay currently has no historical mission-journal timeline. It therefore refuses
session streams with retained mission lifecycle state and requests resnapshotting, instead of
inserting today's assessment into historical evidence frames. Ordinary fresh orientation and
handoff remain available.

## Compatibility and bounds

This is an explicit bounded execution profile, not a complete serializer for
`fss.agent_mission.v1`. The frozen AOP-007 response payload remains the original
`fss.agent_control_plan.v1`; lifecycle state, exact revision, and evidence appear in the registered
response envelope and protected session context. No new top-level operation or effect authority
is introduced. Sessions without enrollment retain their existing prose-only behavior.

The mission journal uses additive record kind `0x4d53` and versioned canonical domains. Older
readers refuse the unknown record instead of dropping mission state. Bounds are 32 enrolled
session/mission identities, 128 revisions per identity, 512 revisions in aggregate, 64 KiB per
revision, and 68 KiB per command. Limit exhaustion refuses further writes.

Focused coverage lives in the owner and durable-journal mission tests,
`deployment_mission_lifecycle_contract`, follow replay/delivery contracts, and the real CLI
agent-effect contract. Full local qualification remains the repository's release authority;
these focused tests and hosted checks do not replace it.
