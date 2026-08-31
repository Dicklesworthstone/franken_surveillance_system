## Stable scope

- Requirement/work-package IDs:
- Gate/readiness dimensions affected:
- Authority, schema, dependency, model, device, privacy, or effect changes:

## What changed

Describe the smallest coherent semantic change and why it belongs in FSS.

## Evidence

- Deterministic/reference tests:
- Fault/cancellation/crash tests:
- Device/model/platform/corpus identities:
- Performance/cost artifacts:
- Negative evidence and known exclusions:

## Claim boundary

State exactly what this PR proves and what it does **not** qualify.

## Checklist

- [ ] Registries, schemas, plan/status, code, and tests agree.
- [ ] No credentials, private captures, household PII, or mutable “latest” artifacts are committed.
- [ ] `bash scripts/qualify.sh --lane policy` passes after regenerating `MANIFEST.sha256`.
- [ ] Rust formatting/check/Clippy/tests pass on the pinned toolchain where Rust changed.
- [ ] New dependencies/authority/durable formats have an ADR and failure analysis.
- [ ] Negative or null results are retained rather than omitted.
