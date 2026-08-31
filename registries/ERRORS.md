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
