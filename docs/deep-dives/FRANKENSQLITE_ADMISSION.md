# FrankenSQLite assimilation admission status (bead fss-x4a.27.52)

Companion to `FRANKENSQLITE.md`: the mechanism-by-mechanism record of where
each admitted MVCC / combine / agent-facing-evidence concept landed in FSS,
with retained evidence.

| Deep-dive mechanism | FSS landing site | Evidence | Status |
|---|---|---|---|
| §2 one canonical version axis for authoritative facts | `EvidenceDeltaBatch` universe: ordered batches, per-object generations, `apply_deltas` monotonicity + `state_root` | `fss-core` evidence module (append/replay/snapshot_at contracts; `evidence_delta_batch` three-way schema realization) | admitted |
| §3 read witnesses (plans record what they relied on) | `CoverageWitness` + read/write witnesses on semantic plans (negative-read gate) | `CoverageWitness` certifies-absence machinery (`require_certified_absence`), witness digests on deltas | admitted |
| §4 negative reads as first-class predicates | `NegativeEvidenceLedger` + `CoverageWitness` requirement | `negative_evidence.rs` (entries, certification, ledger; coverage continuity classes) | admitted |
| §5 hierarchical witnesses permit safe refinement | anchor-pinned derived state + snapshot-at replay | `snapshot_at(sequence)`, replay reproduces terminal anchor (proven in ingest tuya sim contract) | admitted |
| §6 SSI-style dangerous-structure detection | work-claim conflicts + plan invalidation on basis/anchor drift | ERR-AGENT-WORK-CLAIM-CONFLICT, stale-basis refusal (proven for both supersessions in contract_basis tests) | admitted |
| §7 deterministic commit combining | canonical batch ordering (`is_canonically_ordered`, sort keys) + digest self-consistency | contract_basis/evidence tests; batch digest = computed digest | admitted |
| §8 semantic merge ladder | drift repair via typed reconciliation (bead graphs, not silent merges) | `fss-ledger` reconciliation test modules (journal/durable), `repair.rs` | admitted |
| §9 savepoints = staged semantic work | prepare/commit effect split (alert/export/deletion/repair prepare-commit pairs) | capability registry CAP-*-PREPARE/COMMIT rows; effect registry reversibility table | admitted |
| §10 exact numeric ordering is a correctness surface | stable sort keys + generation newtypes (never renumbered) | `sort_key` ordering pinned in evidence tests; stable-ID discipline | admitted |
| §11 recovery is part of the transaction contract | crash-first journal + durable ledger with typed reconciliation | `crash_defects_contract.rs`, `durable_batch_id_reuse_contract.rs`, recovery modules | admitted |
| §12 conflict summaries preserve safety history | tombstoned supersession + negative-evidence retention | tombstone contracts; deletion preserves negative evidence | admitted |
| §13 canonical vs derived data | authority/cognition/effect plane separation (ADR-0001) | semantic plane checker (63 types mapped, doctests verified); `agent_abstraction_stack` typed tower | admitted |

## Deliberately rejected imports (§17) — verified

"Store FSS metadata in SQLite" as the transplant target: the ledger is
first-party pure Rust (`fss-ledger` journal/durable format), no embedded
database engine, no foreign runtime. Physical-world transactionality is
never claimed (battery-cam honesty invariants pin this).

## Verdict

All 12 mapped mechanisms mechanically admitted; the non-obvious import
(observation-history serializability, not a database) is the operative
design everywhere it landed.
