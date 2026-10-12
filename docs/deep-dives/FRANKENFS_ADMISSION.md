# FrankenFS assimilation admission status (bead fss-x4a.27.51)

Companion to `FRANKENFS.md`: the mechanism-by-mechanism record of where each
admitted root-last publication / repair / erasure-code concept landed in FSS,
with retained evidence. Status vocabulary: **admitted** (mechanically
evidenced in-repo), **partial** (core landed, a named aspect pending its
owner bead), **rejected** (deep dive §17, deliberately not imported).

| Deep-dive mechanism | FSS landing site | Evidence | Status |
|---|---|---|---|
| §1 root-last state machine (reserve→…→retire with crash behavior per transition) | `fss-publication` ledger + publication states; `fss-object` spool lifecycle | `process_death_crash_harness.rs`, `local_publication_io_faults.rs`, `staging_spool_io_faults.rs` | admitted |
| §2 staged ≥ visible ≥ durable epoch contract | publication-states vocabulary (`reserved/materializing/verified/published/retired/quarantined/failed/indeterminate` — pinned by `publication_rows_contract.rs`) | architecture/publication_primitives.json states pinned in-test | admitted |
| §3 root-last coherent publication | `fss-publication` root/child proof ordering (`PUB-*` primitives; children verified before root exposure) | `publication_rows_contract.rs` (13 primitives each with root invariant), `local_publication_differential.rs` | admitted |
| §4 mutation authority + repair share one serializer | doctor→sealed-repair-plan→apply (`CAP-REPAIR-PREPARE/COMMIT`) | `doctor0_inspect_contract.rs`, capability registry rows pinned (`capability_rows_contract.rs`) | admitted |
| §5 doctor→sealed repair plan | repair plans as capability-gated effects (prepare/commit split) | capability registry CAP-REPAIR-* rows; effect registry EFFECT rows with reversibility classifications (`effect_rows_contract.rs`) | admitted |
| §6 RaptorQ/self-healing as policy | ATP fountain-coding lane (admission = policy decision, not default) | `atp` skill corpus + transfer beads (FSS-116 family, open — the policy gate exists, implementation tracked) | partial (policy gate admitted; repair-symbol implementation = open ATP lane) |
| §7 generation-aware, evidence-neutral cache | retention/spool policies in `fss-object` (`retention/`, spool admission) | `spool_inspect_contract.rs`, `staging_spool_contract.rs` | admitted |
| §8 content-defined chunking | SEAL_CHUNK_BYTES bounded custody chunking (tutk ingest) | `fss-reference` acquisition seal (`SEAL_CHUNK_BYTES`/`SEAL_MAX_INPUT_BYTES`) | admitted |
| §9 snapshot/clone-on-write | immutable object generations + tombstoned supersession | `tombstone_contract.rs`, stable-ID never-renumber discipline | admitted |
| §10 proof-of-retrievability | retrievability as a publication state + receipts | publication states vocabulary (`retrievable`), qualification receipts | partial (state admitted; remote retrievability campaigns = archive lane) |
| §11 graph-complete deletion + crypto-erasure | deletion closure machinery (walk/commit/index/proof) | `fss-reference/deletion/` (`walk.rs`, `commit/batches.rs`, `index/proof.rs`), `spool_deletion_removal.rs` | admitted |
| §12 capabilities + path confinement | spool path confinement + O_NOFOLLOW-style admission | `bounded_spool_read_contract.rs`, `manifest_input_bounds.rs` | admitted |
| §13 evidence over claim | source-derived inventories + custody digests | manifest digests, `custody_audit_contract.rs`, `authority_custody_contract.rs` | admitted |

## Deliberately rejected imports (§17) — verified still-rejected

General-purpose filesystem role, FUSE in the authoritative path, unconditional
repair symbols, physical-compaction erasing audit history, remote listings as
canonical manifests, in-place mutation of evidence roots: none present — the
canonical manifest is always local+content-addressed; roots are immutable;
deletion preserves negative evidence.

## Verdict

11 of 13 mechanisms mechanically admitted with in-repo evidence; 2 partial
with named open lanes (ATP repair symbols, remote retrievability campaigns).
The rejected-imports list is intact.
