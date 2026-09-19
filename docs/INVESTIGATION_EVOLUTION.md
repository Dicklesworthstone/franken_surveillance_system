# Explicit investigation evolution (FSS-213 / FSS-214 / FSS-229)

The investigation reference now supports changing its question space and explicitly invalidating
its old basis through `investigations::evolution`. These are AOP-006 cognition intents, not new
public fss/1 verbs, source-custody proofs, probe execution, or effect authority.

## Conservative rebase

`ReferenceInvestigationStore::evolve` takes an exact case revision and live session authority.
`Rebase` must name the actual current session anchor: same site lineage and ledger epoch, strictly
increasing commit sequence, nondecreasing adapter-registry epoch, and identical ContractBasis.
The runtime must already have verified that session anchor. Sequence comparison alone does not
prove historical ancestry. Contract upgrades and cross-epoch migration are deliberately refused.

Rebase is allowed only for a nonterminal investigation before its existing decision deadline.
It cannot extend that deadline, reopen a cancelled/resolved/refuted/closed case, reset identity,
remove a hypothesis, rewrite the question, change the privacy domain, or replace stop rules.
It appends a revision naming the exact predecessor and an owner-provided rationale root.

All hypotheses, predictions, citations, contradictory evidence, knowns, unknowns, discriminators,
probe handles and stop rules remain retained. Known and Estimated statement/hypothesis states
become Stale. Conflicted, Unknown, NotObservable, Redacted, Indeterminate, NotApplicable and
already Stale states remain explicit. The old dispositions stay in the immutable predecessor;
the new applicability epoch starts every hypothesis Live and the case AwaitingEvidence. This
is explicit invalidation at a newer anchor, not resurrection of a refuted hypothesis within the
same basis. Terminal cases require a separate new investigation rather than resurrection.

## Old citations are not silently current

The rebased revision records every inherited evidence digest. An assessment using one of those
roots requires `ReadmitCitation` first, with an immutable applicability receipt supplied by the
trusted evidence owner. Readmission is bound to the current full case revision, exact hypothesis,
evidence digest, and supporting/contradicting side. It is not reusable on a different side or
hypothesis. Copying an inherited root to another hypothesis or repeating ordinary `Cite` does
not bypass invalidation. A further rebase invalidates all current citations and previous
readmissions again, preserving earlier receipts in history.

This is an applicability record, not cryptographic source verification. The existing reference
trust boundary remains: the runtime authorizes all input citations and receipt artifacts before
calling it. A made-up receipt digest is not proof of source custody or current physical truth.
New source-owner-authorized citations can be attached normally. Neither readmission nor Assess
upgrades a statement's KnowledgeState. Concluding a rebased case must acknowledge all retained
unknown IDs plus any Stale statements in its knowns lane. Explicit acknowledgement does not
remove the residual or make it Known.

## Append-only alternative expansion

`Expand` appends a new Unknown hypothesis with predictions, an authorized probe handle, and a new
discriminator separating it from at least one existing hypothesis. Expected outcomes must be
aligned with the separated hypotheses and include at least two distinct predictions. Preloaded
evidence, fabricated Known state, duplicate identities, and unresolved hypothesis references
are refused. Citations and later assessments use the ordinary admitted paths.

All prior hypotheses and their exact dispositions remain unchanged, including final refutations
within this basis. Existing statements, uncertainty, citations, deadline and stop rules remain
unchanged. The new hypothesis starts Live, so an otherwise ready conclusion is blocked until
that alternative is explicitly accounted for. No observation is executed by recording the probe.

## Encoding, bounds and compatibility

A never-rebased revision keeps the original canonical bytes and v1 digest domain. Once rebased,
a self-identifying `fss.reference_investigation_validity.v1` extension binds the source revision,
source anchor, rationale, inherited roots and sorted readmission receipts; its private revision
digest uses `fss-reference:investigation-revision:v2`. The existing public InvestigationState
schema remains embedded unchanged. This reference metadata is not a new public wire contract.

All operations recheck session capability, principal, mission and privacy before revealing case
state; the full head digest prevents stale writers from overwriting a newer revision. A refused
evolution appends no case revision but can advance session/store clock watermarks. Every added
revision and validity receipt counts against the existing retained-byte and revision ceilings;
history and fences are not evicted for capacity. The absolute nested schema bounds still apply.

The twelve engine tests cover preserved evidence/residuals, all nine knowledge states, duplicate
citation laundering, cross-hypothesis/side readmission, repeated rebases, fresh citations,
expansion/refutation/conclusion, invalid discrimination, authority drift, stale writers, closed
or expired cases, stale-premise acknowledgement, byte/history capacity and witness identities.
They are committed test source, not execution evidence: this editing environment has no Rust
compiler. Rust tests, rustfmt, clippy and release qualification remain required.

```sh
cargo test -p fss-reference coordination::investigations
```

This engine commit adds in-memory reference evolution. Durable command publication is a separate
integration step; callers must not acknowledge an evolved state from an independently persisted
session or discard the authority state on restart.
