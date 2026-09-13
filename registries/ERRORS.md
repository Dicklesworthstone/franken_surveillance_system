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
| `ERR-CLOCK-STATE-UNKNOWN-001` | clock synchronization state unknown when synchronised evidence required | obtain synchronisation certificate or abstain |
| `ERR-CLOCK-UNSYNCHRONISED-001` | clock unsynchronised or drift bound exceeds tolerance | synchronise clock or bound monotonic drift |
| `ERR-OPERATION-UNREGISTERED-001` | surveillance operation not registered in time uncertainty budget catalog | register operation tolerance before evaluation |
| `ERR-TIME-INTERVAL-INVERTED-001` | capture or transit interval earliest bound exceeds latest bound | correct interval bounds before evaluation |
| `ERR-CLOCK-BASIS-MISMATCH-001` | comparison or association between incompatible clock bases | convert to common basis or synchronise to UTC |
| `ERR-ARITHMETIC-OVERFLOW-001` | arithmetic overflow in timestamp or uncertainty calculation | bound timestamp values within addressable range |
| `ERR-NON-MONOTONE-NARROWING-001` | attempted non-monotone uncertainty narrowing violating FORMAL-010 | preserve monotone widening; retain sync evidence |
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
| `ERR-CLI-UNKNOWN-COMMAND-001` | command token is not a recognized CLI command or verb | do not retry without valid command name |
| `ERR-CLI-UNKNOWN-OPTION-001` | option flag is unrecognized for binary or active command | do not retry without valid option flag |
| `ERR-CLI-MISSING-VALUE-001` | required option or positional argument value is missing | provide required value before retry |
| `ERR-CLI-DUPLICATE-OPTION-001` | option flag was specified more than once | specify option at most once |
| `ERR-CLI-MALFORMED-VALUE-001` | option or argument value cannot be parsed into expected domain | provide valid typed value before retry |
| `ERR-CLI-INVALID-UNICODE-001` | command-line argument contains invalid UTF-8 bytes | encode command-line arguments in UTF-8 |
| `ERR-CLI-UNEXPECTED-POSITIONAL-001` | positional argument provided to command taking no positionals | remove unexpected positional argument |
| `ERR-CLI-TRAILING-ARGUMENT-001` | extra argument provided after command grammar is satisfied | remove trailing argument before retry |
| `ERR-CLI-RUNTIME-FAILURE-001` | runtime error occurred during validated command execution | inspect diagnostic and address failure cause |
| `ERR-OP-EXECUTION-FAILED-001` | operation execution failed with expected domain error | inspect error details and apply recovery guidance |
| `ERR-OP-PRECONDITION-FAILED-001` | tombstone: superseded by `ERR-PRECONDITION-STALE-001` | historical duplicate preserved for audit; canonical target is `ERR-PRECONDITION-STALE-001` |
| `ERR-OP-INDETERMINATE-001` | tombstone: superseded by `ERR-EFFECT-INDETERMINATE-001` | historical duplicate preserved for audit; indeterminate outcomes must use Indeterminate variant |
| `ERR-OP-UNAUTHORIZED-001` | tombstone: superseded by `ERR-AUTH-DENIED-001` | historical duplicate preserved for audit; canonical target is `ERR-AUTH-DENIED-001` |
| `ERR-OP-NOT-OBSERVABLE-001` | tombstone: superseded by `ERR-COVERAGE-UNKNOWN-001` | historical duplicate preserved for audit; canonical target is `ERR-COVERAGE-UNKNOWN-001` |
| `ERR-OP-TIMEOUT-001` | operation budget or deadline expired before completion | retry with higher budget or backoff |
| `ERR-OP-RECONCILIATION-REQUIRED-001` | pending unresolved operation must be reconciled before further mutation | reconcile pending sequence before retry |
| `ERR-OP-ID-MALFORMED-001` | error identity does not conform to stable ERR pattern | fix error identity to match stable registry format |
| `ERR-OP-INVALID-OUTCOME-001` | operation outcome state transition or representation is invalid | inspect outcome payload and repair state machine |
| `ERR-LEDGER-LENGTH-OVERFLOW-001` | journal byte offset or file length exceeds addressable 64-bit bounds | archive or rotate journal; no in-place append possible |
| `ERR-LEDGER-ORACLE-INVALID-CONFIG-001` | ledger oracle limit or site lineage outside its admitted range | repair configuration; do not retry unchanged |
| `ERR-LEDGER-ORACLE-BOUND-001` | batch delta count, child count, or text field exceeds the canonical batch bound | reject input; split or repair the producer |
| `ERR-LEDGER-ORACLE-NON-CANONICAL-001` | batch deltas or child roots are not in strictly increasing canonical order | reject input; re-prepare canonically |
| `ERR-LEDGER-ORACLE-DIGEST-MISMATCH-001` | declared batch digest does not match batch content | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001` | exact batch is already committed at the reported sequence | no retry; batch is already canonical |
| `ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001` | committed batch identity reused with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-DURABLE-BATCH-ID-CONFLICT-001` | durable ledger batch identity already committed with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-ORACLE-CAPACITY-001` | committed-batch capacity of the oracle is exhausted | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-SEQUENCE-GAP-001` | batch basis is beyond the head; predecessor batches are missing | supply predecessors in canonical order, then retry |
| `ERR-LEDGER-ORACLE-BASIS-FORKED-001` | batch basis anchor is not the committed anchor at its sequence | reject input; foreign lineage, epoch, or state root |
| `ERR-LEDGER-ORACLE-SUCCESSOR-CONFLICT-001` | another batch already committed on the same basis (first committer wins) | rebase onto the current head and prepare a new batch |
| `ERR-LEDGER-ORACLE-INVALID-SUCCESSOR-001` | successor anchor lineage, epoch, or sequence does not follow its basis | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-SEQUENCE-EXHAUSTED-001` | commit sequence space is exhausted | archive or rotate; no in-place append possible |
| `ERR-LEDGER-ORACLE-DUPLICATE-OBJECT-001` | one batch carries more than one delta for the same object | reject input; merge or split deltas |
| `ERR-LEDGER-ORACLE-GENERATION-CONFLICT-001` | delta generations do not follow the committed object generation | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-OBJECT-CAPACITY-001` | batch would exceed the live-object capacity of the oracle | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-STATE-ROOT-MISMATCH-001` | declared successor state root does not match the applied deltas | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-STALE-STAGE-001` | staged batch was validated against a head that has since moved or another history | stage again against the current head |
| `ERR-LEDGER-ORACLE-ENCODING-001` | canonical encoding of a digest input exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-LEDGER-ORACLE-READ-BEYOND-HEAD-001` | anchor-pinned read requested a sequence beyond the committed head | wait for commit or read at a committed anchor |
| `ERR-LEDGER-ORACLE-READ-ANCHOR-MISMATCH-001` | anchor-pinned read named an anchor that is not committed in this history | resnapshot from a committed anchor of this lineage |
| `ERR-PUBLICATION-LOCAL-INVALID-CONFIG-001` | local publication limits are zero, inconsistent, or above a format maximum | repair configuration; do not retry unchanged |
| `ERR-PUBLICATION-LOCAL-SLOT-INVALID-001` | publication slot name is empty, too long, or outside the slot grammar | reject input; choose a registered slot name |
| `ERR-PUBLICATION-LOCAL-BOUND-001` | manifest child count or directory entry count exceeds the configured bound | reject input; split the manifest or repair the layout |
| `ERR-PUBLICATION-LOCAL-CAPACITY-001` | configured root or tombstone capacity of the local publisher is exhausted | archive or rotate before publishing |
| `ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001` | a referenced object failed digest verification; root not visible | repair or restage the named object, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001` | a referenced object carries a durable tombstone; root not visible | reject input; tombstoned objects are never republished |
| `ERR-PUBLICATION-LOCAL-UNAVAILABLE-001` | custody of a referenced object could not be determined; root not visible | reopen to reconcile storage, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001` | slot already holds a different visible root | reject input; publish the new root under a new slot |
| `ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001` | slot holds a root record that failed reopen verification | repair or quarantine the broken record; never overwrite it |
| `ERR-PUBLICATION-LOCAL-ORPHAN-TEMP-001` | an orphaned temporary record from an interrupted publication occupies the path | discard classified orphans, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-MANIFEST-MISMATCH-001` | manifest root does not match its canonical body or its staged read-back | reject input; rebuild the manifest canonically |
| `ERR-PUBLICATION-LOCAL-SPOOL-001` | the staging spool refused an object stage, verify, or read | follow the nested spool failure; no root was made visible |
| `ERR-PUBLICATION-LOCAL-IO-001` | a publication filesystem operation failed before the root rename | bounded retry after repairing storage; nothing is visible |
| `ERR-PUBLICATION-LOCAL-LOCKED-001` | another owner holds the exclusive publication lock | wait for the owner to close; never share the root |
| `ERR-PUBLICATION-LOCAL-LAYOUT-001` | a publication directory or record path has the wrong file type or is occupied unexpectedly | repair the layout; nothing is overwritten |
| `ERR-PUBLICATION-LOCAL-INDETERMINATE-001` | root was renamed into place but its directory fsync failed; durability unknown | reopen to reconcile before any retry |
| `ERR-PUBLICATION-LOCAL-ROOT-VISIBILITY-INDETERMINATE-001` | root rename was reported failed and rolling back the possibly renamed record failed; visibility unknown, slot marked indeterminate | reopen to reconcile; the slot is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-VISIBILITY-INDETERMINATE-001` | tombstone rename was reported failed and rolling back the possibly renamed record failed; visibility unknown | reopen to reconcile; the tombstone is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-CLEANUP-001` | removing a temporary publication file failed after an earlier error; both errors are carried | repair storage, discard orphaned temps, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-INJECTED-CRASH-001` | a fault-injection cut point fired and the instance behaves as a dead process | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-CANCELLED-001` | publication was cancelled before the root rename; nothing is visible | retry idempotently when resumed |
| `ERR-PUBLICATION-LOCAL-POISONED-001` | publisher observed a crash or indeterminate outcome and refuses further work | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-DELETION-AUTHORITY-001` | tombstone record lacks a deletion authority witness | supply a verified deletion authority witness |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-CONFLICT-001` | a different tombstone record is already durable for the object | reject input; tombstones are immutable |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-REACHABLE-001` | object is reachable from a visible root and cannot be tombstoned locally | run deletion closure through its owner; no silent unpublish |
| `ERR-PUBLICATION-LOCAL-CORRUPT-TOMBSTONE-001` | a durable tombstone record failed verification on open | repair the tombstone store; open fails closed |
| `ERR-PUBLICATION-LOCAL-ENCODING-001` | canonical encoding of a publication record exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-PUBLICATION-LEDGER-SLOT-IDENTITY-001` | slot cannot be expressed as a stable ledger object or batch identity | reject input; choose a slot within the ledgered slot bound |
| `ERR-PUBLICATION-LEDGER-NOT-DURABLE-001` | slot holds no durable root; its reachability is never committed to the ledger | publish durably or reopen to reconcile first |
| `ERR-PUBLICATION-LEDGER-CONFLICT-001` | canonical ledger already names a different root or family for the slot; nothing appended | repair the ledger identity explicitly; never overwrite either record |
| `ERR-PUBLICATION-LEDGER-PREPARED-MISMATCH-001` | offered batch is not the reachability batch of the slot's durable root | reject input; prepare against the durable root |
| `ERR-PUBLICATION-LEDGER-ALREADY-LEDGERED-001` | root reachability is already canonical; nothing to prepare | no retry; root is already ledgered |
| `ERR-PUBLICATION-LEDGER-UNLEDGERED-001` | root is durable but the ledger refused or could not prepare its reachability batch; explicit pending-ledger state | follow the nested cause, then retry the idempotent ledger commit |
| `ERR-PUBLICATION-LEDGER-INDETERMINATE-001` | root is durable and its reachability append became indeterminate | reconcile the ledger append before any retry |
| `ERR-PUBLICATION-LEDGER-RECONCILIATION-REQUIRED-001` | an indeterminate ledger append must be reconciled before root-ledger work | reconcile the pending ledger append |
| `ERR-PUBLICATION-LEDGER-RECONCILE-001` | reconciling an indeterminate ledger append failed | repair ledger storage, then reconcile again |
| `ERR-PUBLICATION-LEDGER-INJECTED-CRASH-001` | a root-ledger fault-injection cut point fired after the root became durable | reopen both owners to reconcile |
| `ERR-FROZEN-REGISTRY-DRIFT-001` | public operation or resource was added, removed, renamed, or renumbered without a new registry generation | bump the registry generation and update the frozen public registry |
| `ERR-FROZEN-STABLE-ID-REUSED-001` | stable operation or resource identifier was reused for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-FROZEN-TOMBSTONE-RESURRECTED-001` | tombstoned operation or resource was resurrected into active registry | allocate a new identifier; tombstoned entries remain permanently retired |
| `ERR-FROZEN-DIGEST-MISMATCH-001` | frozen public registry digest does not match canonical encoding of sorted rows | recompute canonical freeze digest over sorted rows |
| `ERR-FROZEN-UNREGISTERED-OP-001` | crosswalk or presentation surface references an unregistered operation | register operation in frozen registry or correct surface reference |
| `ERR-CAPABILITY-REGISTRY-DRIFT-001` | capability registry row drift between architecture JSON and markdown | synchronize architecture/capabilities.json and registries/CAPABILITIES.md |
| `ERR-CAPABILITY-UNKNOWN-PLANE-001` | capability specifies an unknown or unregistered semantic plane | assign a recognized semantic plane to the capability row |
| `ERR-CAPABILITY-MISSING-DEFAULT-001` | capability row lacks a default role or default grant policy | declare an explicit default role or default denial in the capability row |
| `ERR-CAPABILITY-STABLE-ID-REUSED-001` | capability stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-CAPABILITY-DIGEST-MISMATCH-001` | capability registry digest does not match canonical encoding of sorted rows | recompute canonical capability registry digest |
| `ERR-CAPABILITY-CORRUPT-FILE-001` | capability registry or markdown documentation file is missing or corrupt | repair or restore capability registry file |
| `ERR-KSTATE-REGISTRY-DRIFT-001` | knowledge state registry row drift between machine registry and markdown | synchronize architecture/knowledge_states.json and registries/AGENT_CONTRACTS.md |
| `ERR-KSTATE-STABLE-ID-REUSED-001` | knowledge state stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-KSTATE-MISSING-FIELD-001` | knowledge state row lacks a mandatory field or is empty/corrupt | declare all mandatory fields in knowledge state row |
| `ERR-KSTATE-CORRUPT-FILE-001` | knowledge state registry or markdown documentation file is missing or corrupt | repair or restore knowledge state registry file |
| `ERR-KSTATE-DIGEST-MISMATCH-001` | knowledge state registry digest does not match canonical encoding of metadata and rows | recompute canonical knowledge state registry digest |
| `ERR-KSTATE-FREEZE-DIVERGENCE-001` | knowledge state registry digest diverged from pinned baseline freeze digest | restore frozen knowledge state registry or bump generation |
| `ERR-KSTATE-GENERATION-MISMATCH-001` | knowledge state registry generation diverged from baseline generation | assign expected generation to knowledge state registry |
| `ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001` | non-known knowledge state illegally authorizes irreversible effect | restrict irreversible effect authorization strictly to known state |
| `ERR-GRAPH-UNREGISTERED-PROJECTION-001` | graph algorithm specifies an unregistered or nonexistent graph projection ID | update algorithm projection to a registered projection ID from docs/GRAPH_ALGORITHM_ATLAS.md |
| `ERR-GRAPH-MISSING-TIE-BREAK-001` | graph algorithm row lacks a deterministic CGSE tie-break rule | specify a deterministic CGSE tie-break policy in graph algorithm registry |
| `ERR-GRAPH-MISSING-COMPLEXITY-WITNESS-001` | graph algorithm row lacks declared complexity witness operations | declare dominant operation complexity witness in graph algorithm registry |
| `ERR-GRAPH-MISSING-OUTPUT-WITNESS-001` | graph algorithm row lacks declared output-size witness with bounds | declare output-size witness with bounds or record explicit owner drift |
| `ERR-GRAPH-PROJECTION-MISMATCH-001` | graph algorithm projections differ between machine source and registry markdown mirror | reconcile machine source and registry markdown projections |
| `ERR-GRAPH-STABLE-ID-DRIFT-001` | graph algorithm stable identifier renumbered or superseded row not tombstoned | restore stable algorithm identity and retain superseded rows as tombstones |
| `ERR-CLAIM-ASSUMPTIONS-MISSING-001` | promoted proof or bounded_model claim declares no assumptions, or an assumption lacks a non-empty id and statement | declare every named assumption before promotion; no retry without them |
| `ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001` | proof claim declares no formal model, or its retained fss.formal_model.v1 manifest or source is missing, unreadable, digest-unbound, or not bound to the claim id | retain the declared formal model bound to the claim id before promotion |
| `ERR-CLAIM-PROOF-MODEL-GENERATION-MISMATCH-001` | proof claim formal model generation differs from the claim generation, the declared model reference, or the check receipt | re-check the proof at the claim generation; never splice generations |
| `ERR-CLAIM-PROOF-THEOREM-UNBOUND-001` | proof claim theorem statement is missing, bound to another claim, or differs from the statement the check receipt checked | bind the exact theorem statement to the claim and re-check |
| `ERR-CLAIM-PROOF-FORMAL-ARTIFACT-MISSING-001` | proof claim formal artifact is absent, not on disk, empty, digest-unbound, or not written in the declared checker language | retain the exact checked formal artifact before promotion |
| `ERR-CLAIM-PROOF-TESTS-ONLY-001` | proof claim is backed only by tests (test-runner toolchain, test source, or test results) instead of a formal artifact | demote the claim or supply a machine-checked formal proof |
| `ERR-CLAIM-PROOF-TOOLCHAIN-UNBOUND-001` | proof claim formal checker identity is missing, unregistered, latest-aliased, or differs between bundle and check receipt | pin the exact registered formal checker and version in bundle and receipt |
| `ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001` | proof check receipt is missing, malformed, non-passing, or not bound to the claim, formal model, and formal artifact digest | re-run the formal checker and retain a passing bound receipt |
| `ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001` | bounded_model claim derivation is missing, not on disk, digest-unbound, malformed, stepless, or not bound to the claim id and generation | retain the fss.bound_derivation.v1 derivation bound to the claim before promotion |
| `ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001` | bounded_model claim bound expression, comparator, or value is missing, non-finite, bound to another claim, or differs from the derivation | bind the exact derived bound expression to the claim |
| `ERR-CLAIM-BOUND-UNITS-MISSING-001` | bounded_model claim bound or derivation declares no units, or the claimed units differ from the derivation units | declare identical explicit units in claim and derivation; never convert implicitly |
| `ERR-CLAIM-BOUND-TIGHTER-THAN-DERIVATION-001` | bounded_model claimed bound is tighter than the analytically derived bound | claim at most the derived bound or retain a derivation supporting the tighter one |
| `ERR-CLAIM-BOUND-SENSITIVITY-MISSING-001` | bounded_model derivation declares no sensitivity analysis or no invalidators | retain sensitivity analysis and invalidators with the derivation |
| `ERR-CLAIM-BOUND-VALUE-OUT-OF-DOMAIN-001` | bounded_model claimed, derived, or input value lies outside its registered unit domain (negative, above 100 percent, above 1 auprc) | correct the value or its unit |
| `ERR-CLAIM-BOUND-DERIVATION-NOT-RECOMPUTABLE-001` | bounded_model derivation records no usable inputs or arithmetic formula, the formula is not its expression right-hand side, or it does not recompute the derived value | record every input with value and units and the exact arithmetic yielding the derived value |
| `ERR-CLAIM-BOUND-DIMENSION-MISMATCH-001` | bounded_model derivation formula is dimensionally inconsistent (+ or - of different units, or propagated units differ from the derivation units) | correct the formula or input units; units are never converted implicitly |
| `ERR-CLAIM-SLO-TARGET-UNBOUND-001` | slo claim target cannot be resolved to exactly one numeric threshold of its registries/SLOS.md row, the measurement declares no or a different unit, or the measurement restates a target that differs from or is non-canonical to the authoritative row | claim only an SLO row with a registered numeric threshold; measure in its exact unit and never restate or relax the target |
| `ERR-CLAIM-SLO-COMPARATOR-OVERRIDE-001` | slo measurement declares a comparator that differs from the comparator of its registries/SLOS.md row | remove the comparator from the measurement; the SLO row alone defines the comparison |
| `ERR-CLAIM-SLO-ACTUAL-INVALID-001` | slo measurement has no single canonical numeric 'actual': it is missing, non-numeric, boolean, negative, overflowing, rounded-only, or shadowed by another actual-like field | retain exactly one finite, non-negative numeric 'actual' in the SLO unit; never report only a rounded value |
| `ERR-CLAIM-SLO-GENERATION-UNBOUND-001` | slo bundle or measurement declares no generation, or the measurement declares no operation-cost registry generation | bind the bundle and measurement to one explicit generation and to the operation-cost registry generation measured against |
| `ERR-CLAIM-SLO-FRESHNESS-BOUND-UNSET-001` | the operation-cost row of an slo measurement declares no measurement_max_age_days, so the freshness bound is unset | a user decision: set the bound on the row; the checker never assumes a default |
| `ERR-CLAIM-SLO-WINDOW-INVALID-001` | slo measurement validity window is missing, unparseable, zone-less, empty, finished before it started, or lies in the future | retain a zone-qualified ISO-8601 measurement window that ended before the evaluation instant |
| `ERR-CLAIM-SLO-MEASUREMENT-NOT-PASSED-001` | slo measurement status is missing or anything other than 'passed' | re-run the measurement; a failed, partial, or unlabelled run never supports an slo claim |
| `ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001` | slo claim retains no single digest-bound fss.environment_manifest.v1 artifact, or the measurement is not bound to that manifest's digest | retain the exact environment manifest and bind the measurement to its digest |
| `ERR-CLAIM-SLO-REGISTRY-INVALID-001` | the SLO registry (registries/SLOS.md) or operation-cost registry (architecture/operation_cost_registry.toml) consulted for an slo claim is missing, unreadable, empty, malformed, or declares no rows or generation | repair the registry under the audited root; slo claims are never checked against a silently skipped registry |
| `ERR-CLAIM-CLASS-UNRESOLVED-001` | a promoted proof bundle's claim id is bound to a claim class by no registry (SLO ids by registries/SLOS.md, invariant ids by architecture/invariants.json); a row Class column or the bundle never resolves it | bind the claim id in its owning registry; no retry until one does |
| `ERR-CLAIM-CLASS-REGISTRY-INVALID-001` | a registry binding claim ids to classes (architecture/invariants.json) declares an inexact id or one id more than once | give every stable id exactly one row |
| `ERR-CLAIM-CLASS-EVIDENCE-UNINSPECTED-001` | promoted claim of a class the checker does not realize with evidence inspection (only slo, proof, bounded_model are realized) | realize the class row or keep the claim unpromoted |
| `ERR-CLAIM-PROOF-STALE-GENERATION-001` | proof bundle references a stale, superseded, tombstoned, expired, or latest-aliased generation, or a generation other than its claim row's current one | re-qualify at the current generation; never splice generations |
| `ERR-CLAIM-PROOF-UNPROVEN-PLACEHOLDER-001` | proof claim formal artifact contains, outside comments and strings, an unproven placeholder (Lean sorry, sorryAx, admit, stop or a confusable lookalike; TLAPS OMITTED in any case) | complete the proof; a placeholder is never a checked proof |
| `ERR-CLAIM-PROOF-UNSOUND-ESCAPE-001` | proof claim formal artifact contains an unsound escape (Lean axiom, native_decide, or user metaprogramming; a standalone TLA+ ASSUME, ASSUMPTION or AXIOM unit) | remove the escape; declare assumptions in the bundle and model |
| `ERR-CLAIM-GENERATION-UNBOUND-001` | promoted proof or bounded_model claim is cited by no claim row declaring its current generation (Generation column), or its citing rows conflict | declare the claim row's current generation and bind the bundle to exactly it |



## Subordinate dependency audit diagnostic registry (DEP-AUD)

The `DEP-AUD-*` namespace provides stable, structured diagnostics emitted during repository policy,
dependency auditing, and build gate qualification (`GATE-000`, `QL-POLICY-001`). Unlike runtime
agent operational errors (`ERR-*`), `DEP-AUD-*` diagnostics identify static configuration, manifest,
target root, or resolved dependency closure violations before compilation and release qualification.

Every `DEP-AUD` finding has a reviewed canonical definition, stable severity, parameter schema,
triggering condition, affected qualification gate, remediation guidance, and exit behavior. Unknown
or drifted IDs are rejected by the policy lane (`scripts/check-policy.py`).

| ID | Severity | Trigger condition | Remediation guidance | Gate effect | Retry policy |
|---|---|---|---|---|---|
| `DEP-AUD-001` | error | required-true dependency-policy key is absent or not true | correct the reviewed allowlist policy value or amend the constitution; never weaken the check | `GATE-000`, `QL-POLICY-001` | repair configuration before re-running qualification |
| `DEP-AUD-002` | error | required-false dependency-policy key is absent or not false | remove the prohibited allowance or complete a reviewed constitutional change; never weaken the check | `GATE-000`, `QL-POLICY-001` | repair configuration before re-running qualification |
| `DEP-AUD-010` | error | a declared workspace member manifest is missing | restore/correct the exact member manifest and source fence before dependency claims | `GATE-000`, `QL-POLICY-001` | restore missing Cargo.toml before re-running qualification |
| `DEP-AUD-011` | error | a dependency section is not a TOML table | repair the manifest shape; do not ignore or coerce malformed dependency declarations | `GATE-000`, `QL-POLICY-001` | reformat dependency section before re-running qualification |
| `DEP-AUD-012` | error | a path dependency escapes the frozen repository or sibling closure | move it into the authorized closure or explicitly admit and pin the dependency | `GATE-000`, `QL-POLICY-001` | retarget path dependency before re-running qualification |
| `DEP-AUD-013` | error | a Git dependency lacks an exact 40-hex revision | pin an immutable reviewed commit and retain source/provenance evidence | `GATE-000`, `QL-POLICY-001` | pin 40-hex git revision before re-running qualification |
| `DEP-AUD-014` | error | a build dependency is present without constitutional admission | remove it or complete the explicit dependency/ADR/security admission; no implicit build scripts | `GATE-000`, `QL-POLICY-001` | remove build-dependencies before re-running qualification |
| `DEP-AUD-015` | error | a direct dependency names a forbidden crate | remove the forbidden crate and repair the design without an unsafe/foreign substitute | `GATE-000`, `QL-POLICY-001` | remove forbidden crate before re-running qualification |
| `DEP-AUD-016` | error | a direct external dependency is outside the closed allowlist | remove it or add a reviewed exact allowlist/DEP/ADR admission with closure proof | `GATE-000`, `QL-POLICY-001` | admit or remove dependency before re-running qualification |
| `DEP-AUD-017` | error | an external dependency does not disable default features | set default-features=false and explicitly admit only audited features | `GATE-000`, `QL-POLICY-001` | set default-features = false before re-running qualification |
| `DEP-AUD-018` | error | workspace-inherited dependency resolution failure or missing workspace key | define the dependency in [workspace.dependencies] or remove workspace = true | `GATE-000`, `QL-POLICY-001` | configure workspace dependency before re-running qualification |
| `DEP-AUD-019` | error | an undeclared non-member path crate was detected within the repository tree | declare the path crate in workspace members or remove it from the repository tree | `GATE-000`, `QL-POLICY-001` | declare member or remove crate before re-running qualification |
| `DEP-AUD-020` | error | a crate has no inspectable Rust target root | restore/register the target root so unsafe and production-boundary policy is verifiable | `GATE-000`, `QL-POLICY-001` | add target root before re-running qualification |
| `DEP-AUD-021` | error | a Rust target root lacks unconditional forbid unsafe_code | add the unconditional crate-level prohibition; no local exception path exists | `GATE-000`, `QL-POLICY-001` | add #![forbid(unsafe_code)] before re-running qualification |
| `DEP-AUD-022` | error | FSS Rust source contains a forbidden production construct | remove unsafe, native/dynamic/foreign runtime, second executor, or prohibited construct | `GATE-000`, `QL-POLICY-001` | remove forbidden construct before re-running qualification |
| `DEP-AUD-023` | error | a serde-family codec crate or Serde derive/path/attribute is present in FSS manifests, Cargo.lock, or Rust source | remove it and encode durable bytes with the first-party canonical codec; no non-durable serde admission path exists (FSS-110) | `GATE-000`, `QL-POLICY-001` | replace the Serde use with the canonical codec before re-running qualification |
| `DEP-AUD-024` | error | workspace membership duplicate or ambiguous across glob and explicit patterns | ensure each member directory and crate name is uniquely declared once in workspace.members | `GATE-000`, `QL-POLICY-001` | eliminate duplicate members before re-running qualification |
| `DEP-AUD-025` | error | declared workspace root manifest lacks [workspace] table | add [workspace] table to root Cargo.toml or correct the workspace path | `GATE-000`, `QL-POLICY-001` | add [workspace] table before re-running qualification |
| `DEP-AUD-026` | error | a build script contains a network-capable construct on the static deny-list | remove the network access; build scripts must run offline and stay refused by DEP-AUD-031 (static deny-list, not proof of absence) | `GATE-000`, `QL-POLICY-001` | remove network access from the build script before re-running qualification |
| `DEP-AUD-027` | error | a qualification script (scripts/qualify.sh or scripts/release_qualify.sh) does not seal Cargo and rustup offline (missing top-level CARGO_NET_OFFLINE=true or RUSTUP_AUTO_INSTALL=0 export, an override, a cargo invocation without --offline, or a network-fetching rustup command such as rustup install/update, rustup toolchain install, or rustup run --install) | export CARGO_NET_OFFLINE=true and RUSTUP_AUTO_INSTALL=0 at top level and pass --offline to every cargo invocation in scripts/qualify.sh and scripts/release_qualify.sh, and never install or update toolchains, components, or targets there; this is Cargo/rustup sealing, not OS network isolation | `GATE-000`, `QL-POLICY-001` | seal scripts/qualify.sh and scripts/release_qualify.sh offline before re-running qualification |
| `DEP-AUD-028` | error | the rust lane of the qualification entrypoint has no recorded cargo test --workspace --doc step, so doctests (never run by --all-targets) are unqualified | add a recorded `run doctest ... cargo test --locked --offline --workspace --doc` step inside rust_lane() in scripts/qualify.sh (fss-tgwit) | `GATE-000`, `QL-POLICY-001` | add the doctest step before re-running qualification |
| `DEP-AUD-030` | error | a forbidden package is reachable in resolved Cargo metadata | remove it from the entire transitive closure and regenerate locked evidence | `GATE-000`, `QL-POLICY-001` | remove transitive forbidden dependency before re-running qualification |
| `DEP-AUD-031` | error | a resolved package has a custom build target | remove or constitutionally admit the build script with exact offline/security proof; pure-Rust production | `GATE-000`, `QL-POLICY-001` | remove or admit build script before re-running qualification |
| `DEP-AUD-032` | error | a resolved package declares native links | remove native linkage or complete a constitutional architecture change; pure-Rust production | `GATE-000`, `QL-POLICY-001` | eliminate native links before re-running qualification |
| `DEP-AUD-033` | error | a resolved Git package source is not commit-resolved | pin and lock an immutable exact commit with source/provenance evidence | `GATE-000`, `QL-POLICY-001` | lock exact commit revision before re-running qualification |
| `DEP-AUD-040` | error | required pinned-nightly offline Cargo metadata is unavailable | restore exact toolchain/cache/lock/sibling closure and rerun; policy-only execution cannot certify release | `GATE-000`, `QL-POLICY-001` | restore toolchain/cache before re-running qualification |
| `DEP-AUD-041` | warning | target census drift between reference model and cargo metadata | reconcile target roots with cargo metadata to ensure no target is hidden or missing | `GATE-000`, `QL-POLICY-001` | reconcile target roots before re-running qualification |

## Process exit identity registry (EXIT)

Stable process exit identities map command-line interface outcomes to deterministic exit codes and registered identities.

| Exit ID | Code | Meaning | Recovery guidance |
|---|---|---|---|
| `EXIT-OK-000` | 0 | successful execution | no recovery needed |
| `EXIT-CLI-RUNTIME-FAILURE-001` | 1 | runtime execution failure | inspect error output and address underlying cause |
| `EXIT-CLI-UNKNOWN-COMMAND-002` | 2 | unknown command specified | consult help and run a registered command |
| `EXIT-CLI-UNKNOWN-OPTION-002` | 2 | unknown option specified | consult help and provide registered options |
| `EXIT-CLI-MISSING-VALUE-002` | 2 | missing value for option | provide required parameter value |
| `EXIT-CLI-DUPLICATE-OPTION-002` | 2 | duplicate option specified | specify option at most once |
| `EXIT-CLI-MALFORMED-VALUE-002` | 2 | malformed value specified | supply value matching required format and bounds |
| `EXIT-CLI-INVALID-UNICODE-002` | 2 | invalid UTF-8 argument | supply valid UTF-8 argument bytes |
| `EXIT-CLI-UNEXPECTED-POSITIONAL-002` | 2 | unexpected positional argument | remove unexpected positional arguments |
| `EXIT-CLI-TRAILING-ARGUMENT-002` | 2 | trailing argument after grammar exhaustion | remove trailing arguments |

