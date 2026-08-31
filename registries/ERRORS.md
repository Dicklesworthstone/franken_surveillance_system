# Stable error registry

Errors are machine identities with structured fields. Human text can improve without changing the
contract. Cancellation and panic remain distinct outcome channels; indeterminate effects are
operation states rather than generic errors.

| ID | Meaning | Retry policy |
|---|---|---|
| `ERR-AUTH-DENIED-001` | principal lacks exact capability | do not retry without new authority |
| `ERR-SECRET-UNAVAILABLE-001` | secret handle cannot be resolved | repair/rotate; bounded retry if provider transient |
| `ERR-DEVICE-UNSUPPORTED-001` | exact product/firmware/app tuple not certified | fail closed or explicit import-only mode |
| `ERR-FIRMWARE-DRIFT-001` | observed device generation differs from registry | disable/move to shadow; no optimistic retry |
| `ERR-ADAPTER-PROTOCOL-001` | adapter response violates typed protocol | terminate adapter generation; retain fixture |
| `ERR-STREAM-NO-FIRST-FRAME-001` | adapter accepted but no decodable frame before budget | reconnect or fail; never claim coverage |
| `ERR-STREAM-CONTINUITY-001` | gaps/jitter exceed contract | degrade coverage; bounded recovery |
| `ERR-CLOCK-UNCERTAIN-001` | capture interval too wide for requested operation | degrade/abstain/recalibrate |
| `ERR-DECODE-001` | media decode failed | preserve source; alternate decoder only if registered |
| `ERR-DECODE-BOUNDS-001` | media exceeds declared bounds | fail closed |
| `ERR-MODEL-UNAVAILABLE-001` | model generation not runnable | route to registered fallback or degrade |
| `ERR-MODEL-OUTPUT-001` | malformed/out-of-bounds model output | reject output; terminate/quarantine generation |
| `ERR-MODEL-GENERATION-001` | mixed or stale model/index generation | rebuild/retry at coherent generation |
| `ERR-CALIBRATION-INVALID-001` | certificate expired/invalidated/residual failure | no geometry-dependent negative evidence |
| `ERR-COVERAGE-UNKNOWN-001` | effective observability cannot be established | abstain/escalate health alert |
| `ERR-EVIDENCE-MISSING-001` | canonical root references unavailable required evidence | repair; no adjudication requiring it |
| `ERR-PUBLICATION-PARTIAL-001` | child staging incomplete; root not visible | idempotent retry or collect children |
| `ERR-ARCHIVE-UNREACHABLE-001` | remote archive unavailable | local spool obligation; bounded retry |
| `ERR-ARCHIVE-VERIFY-001` | published object failed retrieval/integrity check | quarantine/repair/escalate |
| `ERR-IDEMPOTENCY-CONFLICT-001` | same key used with different request digest | reject permanently |
| `ERR-EFFECT-INDETERMINATE-001` | dispatch outcome cannot be determined | reconcile before retry |
| `ERR-LEASE-STALE-001` | effect lease fence is not current | re-prepare under fresh lease |
| `ERR-PRECONDITION-STALE-001` | plan anchor changed before commit | re-plan; never auto-commit changed intent |
| `ERR-PRIVACY-MASK-001` | required redaction could not be applied | fail closed at restricted boundary |
| `ERR-DELETION-BLOCKED-001` | deletion closure blocked by hold/backend/offline copy | report exact blockers and obligation |
| `ERR-BUDGET-EXHAUSTED-001` | declared work budget exhausted | return bounded partial/abstention |
| `ERR-REPLAY-DIVERGED-001` | semantic decision fingerprint differs from proof | block claim/release |
| `ERR-QUIESCENCE-001` | region/process failed to drain | block shutdown/upgrade claim; force isolation path |
| `ERR-SCHEMA-UNSUPPORTED-001` | input durable schema version unsupported | migrate with registered path or reject |
| `ERR-INTERNAL-PANIC-001` | boundary converted an internal panic to structured crash receipt | quarantine, preserve support bundle |
| `ERR-AGENT-SESSION-STALE-001` | session, workspace, or resumed handoff basis no longer satisfies required anchor/generation/freshness semantics | rebase and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding |
| `ERR-AGENT-AMBIGUOUS-001` | natural-language request has multiple materially different interpretations | return interpretations; choose only a registered safe-read default or request clarification |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | requested decision-complete context cannot fit or lacks required evidence | return bounded partial with omissions/expansion handles; never imply completeness |
| `ERR-AGENT-HANDOFF-INVALID-001` | handoff root is incomplete, expired, unauthorized, schema/generation-incompatible, or cannot be safely rebased | reject, migrate, or open a new session with an explicit invalidation report; never silently resume |
| `ERR-AGENT-WORK-CLAIM-CONFLICT-001` | requested multi-agent work scope overlaps an incompatible live claim, lease, or fence | narrow, wait, delegate, release, or supersede with explicit authority; never last-writer-wins |
| `ERR-AGENT-NO-AFFORDANCE-001` | no safe, authorized, useful next action exists under current evidence/budget | explain blocking clamps and return wait/escalate/stop reason |
| `ERR-AGENT-LEARNING-UNSUPPORTED-001` | learning proposal lacks evidence, applicability, counterexamples, or validation path | retain as rejected/advisory; do not activate |
| `ERR-AGENT-TRANSPORT-DIVERGED-001` | CLI/MCP/TUI/report semantic payload or digest differs for equivalent input | block affected surface/release and retain differential transcript |
| `ERR-AGENT-RESUME-INDETERMINATE-001` | external effects/obligations prevent a truthful resumed terminal state | resume in reconciliation mode; no effect retry before lookup/proof |
| `ERR-AGENT-RESNAPSHOT-001` | continuation cannot advance coherently from its exact basis | request a fresh situation capsule; do not splice generations |
| `ERR-AGENT-AFFORDANCE-INVALIDATED-001` | recommended next move lost a precondition, capability, lease, or validity interval | refresh/replan; never execute cached recommendation |
| `ERR-AGENT-CASE-BUDGET-001` | investigation cannot discriminate remaining hypotheses within declared budget | return residual uncertainty and explicit next probe/approval options |
| `ERR-AGENT-PROTOCOL-001` | presentation attempted an unregistered verb/view or changed semantic meaning | reject and repair registry/transport drift |
| `ERR-AGENT-HIDDEN-STATE-001` | required mission state exists only in conversation or caller memory | persist typed mission/workspace/case/plan/finding/handoff state before proceeding |
