# Captured episode experience and learning candidates

The AOP-013 `feedback` operation can turn an owned plan's retained terminal execution episode
into an immutable `ExperienceCapsule` and an evidence-linked `LearningProposal`. This connects
execution closure to the advisory learning path described by comprehensive plan §20.13 and
FSS-230/231/232. It does not establish the real-world correctness of the original surveillance
interpretation or complete the broader learning qualification gates.

## Capture through the existing operation

Close the original plan using the existing `plan --close` operation. Then cite evidence from its
verified source publications:

```sh
fss feedback --json --root DEPLOYMENT --session SESSION \
  --target plan:PLAN --kind runbook_candidate \
  --statement "Retain this cancellation procedure for review." \
  --supporting sha256:SOURCE_EVIDENCE \
  --disposition create_learning_proposal
```

MCP uses the same `feedback` tool and fields:

```json
{
  "session": "session:returned-by-open",
  "target": "plan:plan:returned-by-plan",
  "kind": "runbook_candidate",
  "statement": "Retain this cancellation procedure for review.",
  "supporting": ["sha256:REPLACE_WITH_A_REAL_SOURCE_DIGEST"],
  "disposition": "create_learning_proposal"
}
```

Target parsing preserves the literal identity after the first prefix: a plan whose native identity
is `plan:abc` is targeted as `plan:plan:abc`. The example digests and identities are placeholders.

The feedback capability, principal, session, mission, original plan, retained episode, current
authority and complete source custody must all admit the capture. A plan must belong to the
requesting session; another session under the same principal cannot borrow its outcome. A missing
or corrupt source object is a refusal, never an empty or successful experience.

The capture profile accepts the existing feedback kinds and evidence sets. Its statement limit is
8,192 UTF-8 bytes, matching the native learning record. Ordinary feedback retains its 16,384-byte
native bound. Supporting and contradicting citations remain distinct, including a citation that
appears on both sides. Other targets or dispositions retain their existing feedback-only behavior.

## Retained meaning

The original feedback publication remains immutable. Capture publishes a separate root-last graph
that binds the source plan, episode and feedback to canonical experience and learning records.
The experience preserves the mission and objective, source anchors, attempted operation, terminal
execution outcome, original uncertainty, evidence and restricted applicability. Its situation
signature identifies the retained plan publication and its witnesses; it does not claim to
reconstruct the complete original SituationCapsule.

The learning candidate starts `captured`. Its class is derived from the registered feedback kind.
Feedback labels such as `helpful` and `harmful` do not establish causal attribution or increment
validated outcome counts. A single episode remains `single_episode`; confidence and outcome
counts do not become corroboration or held-out validation.

Review, expiry, counterexamples, exclusions and required validation remain part of the captured
proposal. This bounded profile schedules review seven evidence-clock days after the retained
source time and expiry after thirty days; an exact retry preserves both deadlines. No capture promotes a candidate, changes a model or policy, widens authority, alters
retention/privacy, or dispatches an effect. Literal candidate text remains advisory content.

## Response and exact recovery

A successful capture returns the already-registered `fss.experience_capsule.v1` payload in the
ordinary agent response envelope. The capture operation can succeed while its learning knowledge
remains `unknown` and its evidence completeness remains `partial`. `candidateTemplates` exposes
the literal candidate statement.
The first proof pointers identify:

| Position | Retained identity |
| --- | --- |
| 0 | Experience/learning publication root |
| 1 | SHA-256 of canonical experience child bytes |
| 2 | SHA-256 of canonical learning-proposal child bytes |
| 3 | Original episode publication root |
| 4 | Original feedback publication root |
| 5 | Original plan publication root |
| 6 | Session orientation anchor token |

The child hashes identify bytes in the publication graph. The decision fingerprint separately
uses the experience type's domain-separated canonical digest.

An exact request retry revalidates authority and the complete source/learning graph and recovers
the retained identities. It does not rewrite an earlier feedback publication, replace a damaged
learning graph, extend the captured expiry, or manufacture a new outcome. A preexisting feedback
record from an older producer can acquire its separate learning publication once its episode is
available and valid.

If feedback is retained but capture fails, the command returns a typed `partial` envelope and a
refusal exit status. Its payload and proof pointers identify the retained feedback; the execution
boundary says which publication completed and whether further publication progress is uncertain.
After resolving the failed precondition, retry the same request. Never delete retained feedback
to hide uncertain publication progress.

## Cost and evidence limits

The source episode's exact resource measurements remain bound by the publication graph.
Dimensions the source did not meter are explicit in the canonical epistemic map, the response's
`missingEvidence`, and its degradation statements. The numeric cost vector carries lower bounds;
it is not a certified full task or capture cost, and zero is not a claim that an unmetered resource
was free. Cost-model changes and policy/effect decisions require separate complete measurement and
validation.

The native and actual CLI/MCP regressions cover terminal-source admission, cold recovery,
canonical child custody, partial feedback preservation, principal/session isolation and
noninterference with evidence, effects and active policy. Hosted checks supplement the repository's
local qualification authority; this bounded path does not claim complete learning promotion or
release qualification.
