# Plan errata and canonical resolutions

This file records compatibility-preserving corrections to already-published plan text. It does not
silently rewrite the historical comprehensive plan.

## 2026-09-01

### Dependency exception wording

`COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md` §27.3 says the default external exception
set includes Serde, Serde JSON, and Thiserror. The canonical machine policy in
`architecture/dependency_allowlist.toml` admits only `serde` and `serde_json` as fundamental
exceptions. `thiserror` remains a non-admitted candidate. The machine allowlist wins.

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
