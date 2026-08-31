# Franken import admission gates

**Document class:** normative cross-project integration gate
**Revision:** 1
**Date:** 2026-08-31
**Machine registry:** [`../architecture/franken_imports.json`](../architecture/franken_imports.json)

## 1. Semantic import precedes physical dependency

A sibling project can contribute a contract before FSS links its implementation. Each imported mechanism moves through:

```text
Censused
→ Contracted
→ ReferenceImplemented
→ AdapterImplemented
→ DifferentiallyVerified
→ FaultVerified
→ PerformanceMeasured
→ ProductionAdmitted
```

No dependency declaration, code presence, unit test, or sibling README claim skips a stage.

## 2. Required mechanism fields

Every `INT-*` mechanism records:

- source project and exact inspected surfaces;
- mechanism and FSS semantic owner;
- invariant established;
- substitute prohibition;
- deterministic reference model;
- failure/degraded boundary;
- required admission evidence;
- current maturity;
- replacement/rollback path.

## 3. Gate dimensions

### Contract gate

Stable types/states/errors/IDs exist and documentation agrees.

### Reference gate

A simple deterministic implementation or executable oracle defines semantics.

### Ownership/cancellation gate

All work, resources, obligations, and external calls have owners and terminal behavior.

### Differential gate

Optimized/imported behavior matches the reference on generated, real, and adversarial corpora; differences are classified.

### Fault/recovery gate

Cancellation, crash, corruption, partial I/O, reorder, duplication, stale generation, and resource pressure preserve the contract.

### Security/privacy gate

Authority is narrowed before data access/expansion; secrets and private counts/absence cannot leak.

### Performance gate

Same-binary evidence shows a material benefit on representative workloads without semantic drift.

### Operational/release gate

DSR can build, qualify, package, and reproduce the exact sibling closure on supported targets.

## 4. Failure behavior

If an imported implementation is unavailable or loses its gate:

- authoritative semantics stay with the reference path where feasible;
- optional optimization/cognition degrades explicitly;
- unsupported effect/adapter/model capability fails closed;
- existing immutable evidence remains readable;
- the system reports the exact missing gate and repair action;
- no fallback introduces a forbidden dependency or weaker authority model.

## 5. Aggregate project status is forbidden

A sibling can be excellent overall and still unqualified for one FSS mechanism. Conversely, an experimental sibling can provide a precisely qualified primitive. FSS claims mechanism-level admission, exact revision, workload, platform, and limits—not “integrated with project X.”
