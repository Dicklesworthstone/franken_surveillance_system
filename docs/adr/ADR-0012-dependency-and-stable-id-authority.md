# ADR-0012 — Machine dependency allowlist and stable-ID resolution are authoritative

**Status:** Accepted  
**Date:** 2026-09-01

## Context

Two P0 specification drifts were found after the first public architecture release.

1. A sentence in the comprehensive plan described `thiserror` as part of the default external
   exception set, while the machine dependency allowlist correctly kept `thiserror` in
   `exception_candidates.not_admitted_without_dep_record_adr_and_release_evidence`.
2. `GOAL-019`, `GOAL-020`, `NS-9`, and `NS-10` were each published twice with different semantic
   meanings. The repository's previous stable-ID census collected matches into a Python `set`, so
   those collisions produced a false green.

Neither problem justifies silently rewriting published history.

## Decision

The machine dependency allowlist is authoritative for dependency admission. `thiserror` remains
**not admitted**. The live Cargo workspace is dependency-free except for the internal `fss-core`
path dependency used by `fss-cli`. A future `thiserror` admission requires its own `DEP-*` record,
ADR, locked dependency census, and release evidence.

Published collided goal/scenario headings remain byte-stable for historical auditability.
`architecture/stable_id_resolution.json` resolves each collided occurrence by exact
`legacyId + titleDigest` to one canonical ID. The second semantic meanings become `GOAL-024`,
`GOAL-025`, `NS-14`, and `NS-15`. New references MUST use the canonical ID.

`scripts/stable_id_audit.py` is release-blocking through `scripts/qualify.sh`. It fails on:

- an unresolved duplicate definition;
- a reused canonical ID;
- a changed title fingerprint;
- a stale resolution row;
- a missing or extra canonical goal/North-Star definition.

The old set-valued count in `check-policy.py` remains only an informational repository census and
is no longer evidence that definitions are collision-free.

## Consequences

- Dependency prose cannot widen the executable dependency universe.
- Historical identifiers remain inspectable without pretending collisions never happened.
- Future automation can refer to canonical IDs without ambiguity.
- A title edit to a collided historical definition is a compatibility change and must update this
  ADR/resolution protocol deliberately.
- Beads and proof bundles should record canonical IDs and may additionally retain legacy aliases.

## Rejected alternatives

**Renumber the old headings in place.** Rejected because published stable IDs are append-only
semantic history, not mutable labels.

**Admit `thiserror` merely to match prose.** Rejected because no live crate needs it and the closed
dependency doctrine requires demonstrated necessity rather than documentation convenience.
