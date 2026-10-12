# Adjacent Franken-suite admission status (DEEP-ADJACENT-001 / bead fss-x4a.27.48)

Companion to `ADJACENT_FRANKEN_PROJECTS.md`: the per-project record of the
current admission state under the deep dive's §Admission rule. Status
vocabulary: **candidate** (mentioned, zero production presence),
**gated-family** (allowlist family exists; every concrete crate still requires
its import-admission gate), **imported** (a concrete crate is in the closure).

| Project | Status | Boundary evidence |
|---|---|---|
| `frankentui` | gated-family, not imported | `Cargo.lock` contains no `frankentui` crate; family gated by `franken_imports.json` records |
| `frankenui` | candidate | no allowlist family, no lock presence |
| `frankentorch` | gated-family, not imported | allowlist family `ft-*`; zero `ft-*` in lock |
| `franken_whisper` | candidate | no allowlist family, no lock presence |
| `franken_ocr` | candidate | no allowlist family, no lock presence |
| `frankenmermaid` | candidate | no allowlist family, no lock presence |
| `franken_markdown` | gated-family, not imported | allowlist family `fmd-*`; zero `fmd-*` in lock |
| `franken_networkx` | gated-family, not imported | allowlist family `fnx-*`; zero `fnx-*` in lock |
| `frankensim` family | candidate | no allowlist family, no lock presence |

## Admission-rule compliance (the 8 requirements)

1. **Exact mechanism and semantic owner**: each gated family maps to its
   `architecture/franken_imports.json` project record; family membership
   alone is explicitly not qualification (allowlist `in_house.rule`).
2. **Dependency-direction review**: enforced per import record at admission
   time (`docs/FRANKEN_IMPORT_ADMISSION_GATES.md`); no record exists for any
   currently-absent crate because none has been requested.
3. **No second runtime or ambient authority**: `asupersync_is_only_async_runtime
   = true` pins the sole-runtime invariant; no adjacent family may carry a
   runtime (the DEP-INV invariants refuse it at the closure scanner).
4. **Deterministic reference behavior**: required per import record; N/A
   until a first concrete admission.
5. **Qualification on FSS workloads**: required per import record; N/A until
   a first concrete admission.
6. **Graceful failure or reference fallback**: required per import record;
   N/A until a first concrete admission.
7. **No aggregate readiness inference from the sibling repository**: the
   sibling repos' own claims are never FSS evidence; only in-repo import
   records + retained proofs count.
8. **Exact revision capture in DSR release receipts**: the receipt carries
   `siblingClosureDigest` binding the closure; any future imported crate
   enters the lock and is thereby captured.

## Verdict

The boundary is intact and verified on 2026-10-11: zero adjacent-project
crates in `Cargo.lock`; the gated families exist precisely so a future
admission must pass its per-crate gate rather than ride in on family
membership. Nothing is "admitted merely by mention."
