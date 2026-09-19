# Plan errata and canonical resolutions

This file records compatibility-preserving corrections to already-published plan text. It does not
silently rewrite the historical comprehensive plan.

## 2026-09-01

### Dependency exception wording

`COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md` §27.3 says the default external exception
set includes Serde, Serde JSON, and Thiserror. The canonical machine policy in
`architecture/dependency_allowlist.toml` admits only `serde` and `serde_json` as fundamental
exceptions. `thiserror` remains a non-admitted candidate. The machine allowlist wins.

Resolved 2026-09-19 (DRIFT-008): §27.3 now names only `serde` and `serde_json`;
`thiserror` is stated as a non-admitted exception candidate requiring a DEP record, ADR, and
release evidence, matching `architecture/dependency_allowlist.toml` `[resolved_drifts]`.

### Collided stable definitions

The following historical definitions collided. Canonical resolution is machine-owned by
`architecture/stable_id_resolution.json`:

| Legacy occurrence | Canonical ID |
|---|---|
| `GOAL-019` — Agent legibility | `GOAL-019` |
| `GOAL-019` — Agent epistemic ergonomics | `GOAL-024` |
| `GOAL-020` — Cognitive economy | `GOAL-020` |
| `GOAL-020` — Agent accretion | `GOAL-025` |
| `NS-9` — Cold-start orientation | `NS-9` |
| `NS-9` — Cold resume after agent and host loss | `NS-14` |
| `NS-10` — Ambiguous event under a hard budget | `NS-10` |
| `NS-10` — Cheapest decisive observation | `NS-15` |

New references use the canonical IDs. Historical prose stays unchanged so old proof bundles and
commit links remain interpretable.

## 2026-09-17 — Seed completeness reconciliation

DRIFT-003 reconciles the superseded first-240 issues claim in the plan TOC, Appendix F
heading, and README with the already-published final seed identity `FSS-250`.
The owner is PROGRAM-GOV; `architecture/seed_requirements.json` is the version 1 canonical
machine catalog. Its ordered rows preserve all identities and complete multiline intents;
the plan list and all three count mirrors derive from that catalog. There are no deleted,
merged, reused, renumbered, or tombstoned requirements. The crosswalk is identity-to-itself.

This is a prose/count correction, not a runtime format migration or implementation claim.
Old source links and proof bundles remain interpretable; the historical source digests and
extracted identities are retained in `tests/fixtures/seed_requirements/before.json`.
A future count or intent change requires a reviewed catalog version, migration/crosswalk,
explicit claim impact, and admission update; recomputing a digest alone is not authority.

The guard is shared with the architecture consistency checker. Run
`python3 scripts/seed_requirement_checker.py --out target/seed-proof` to scan the public
contract corpus and retain deterministic positive, negative, and recovery evidence, then
`python3 scripts/seed_requirement_checker.py --verify target/seed-proof` to independently
verify its content-addressed root, transcript, and artifacts. JSONL records are validated
against the closed fixture schema using the repository's existing JSON Schema validator.
No source prose, credentials, or media enters diagnostics; only public source digests,
stable identities, counts, and locations are emitted. Budgets and terminal obligations are
explicit. Proofs expire on any scanned source or checker generation change.

Affected claims are GATE-000 architecture coherence, WP-000 bootstrap qualification, and
the dependent GATE-120 release closure. They remain blocked until the retained seed proof
and their other prerequisites pass; resolving this drift does not imply those gates pass.
Other stable-ID collisions and dependency-policy drift retain their existing resolutions.
