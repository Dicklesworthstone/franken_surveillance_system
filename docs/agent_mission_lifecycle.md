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

The command response identifies whether its retained revision is current or historical, even
though its payload remains the original control plan. If response generation fails after a
revision is retained, a refusal must preserve that possibility; it is not proof that enrollment
or assessment never happened. Read the authorized retained head with the session orientation
command below before choosing an exact retry. A context-capacity refusal does not mean the
journal is corrupt.

## Orientation, handoff, and recovery

Session orientation protects the original prose, explicit execution objective, criterion,
selected plan/event/operation/obligation, deadline, revision, and freshness statement. The
objective identity is stable across assessments; decision fingerprints bind each exact revision.
Only a current assessment supplies the capsule's typed mission state. Changes to evidence,
effect history, or the scoped closure inventory make a retained assessment historical, including
when new work appears after a terminal result. Historical terminal proof remains inspectable;
it does not assert current completion.

A session that retains mission read access after its capabilities are narrowed still sees its
authenticated revision, criterion, deadline, and retained proof roots. If its grants no longer
permit complete closure validation, the projection marks that assessment historical and leaves
the current mission state unassessed. It does not erase the enrollment or recover mutation
authority from the retained record. Existing workspace operations still refuse when narrowed
grants cannot admit the wider workspace; the read path does not bypass that check.

Handoffs carry nonempty success/failure/stop criteria for enrolled objectives, their proof
pointers, and the canonical lifecycle revision as a root-last publication child. The workspace's
original objective digest is not rewritten. Cold session-journal replay and agent backup history
retain all immutable mission revisions and their expected-predecessor commands.

Follow replay currently has no historical mission-journal timeline. It therefore refuses
session streams with retained mission lifecycle state and requests resnapshotting, instead of
inserting today's assessment into historical evidence frames. Ordinary fresh orientation and
handoff remain available.

## Read the current situation for an existing session

An existing session can be inspected directly without creating a handoff or resuming it:

```sh
fss session orient --json --root DEPLOYMENT --session SESSION --view brief
```

The existing `fss orient` alias accepts the same selector. MCP `session_orient` accepts an
optional `session` string under the server's fixed principal and deployment. Omit the selector
for the existing deployment-only orientation.

For an enrolled mission, the first response `proofPointers` entry is the exact retained mission
revision digest, matching the convention used by `mission-bind` and `mission-assess`. It is
available from enrollment revision zero onward, even when the assessment has become historical.
After a lost command response, read this digest and pass it as `--expected-mission` to assess
the original plan. The payload's `missionRevision` is the retained revision number; freshness
remains a separate protected statement and typed mission-state decision. A historical digest
does not claim current completion or authorize another effect. An unchanged terminal retry
returns the retained result without appending another revision. Sessions without enrollment
retain their ordinary proof-pointer ordering.

The native reader authenticates the existing session journal and mission publication, admits
the principal and workspace, and compiles the current deployment situation with the session's
mission, execution criteria, progress, cases, plans, claims, findings and supervision metadata.
It does not create or repair a store, append a record, renew a lease, charge the durable session
budget, or rebase the workspace. Explicit view limits still apply; protected context that does
not fit is refused instead of truncated.

The response's anchor names the current projection. Its workspace revision and `previousAnchor`
identify the retained workspace. If the deployment has advanced, old assumptions are marked
invalid and next actions must be re-derived; the retained workspace remains unchanged. The
complete historical session comparison is unavailable, so `meaningfulDelta` remains null.
Current mission assessment freshness is rechecked under the same proof and scoped-closure
rules used by lifecycle commands. A historical terminal revision is preserved without being
presented as current completion.

Control-generation, capability and privacy changes must still admit the current read; it never
restores permission from an older workspace. Unknown, foreign, closed, expired, corrupted or
unauthorized session state is refused. A
failed read cannot initialize missing continuity files or silently fall back to an unrelated
deployment-only session. To change the retained workspace basis, use the existing explicit
handoff/resume operations after reviewing the current situation.

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
