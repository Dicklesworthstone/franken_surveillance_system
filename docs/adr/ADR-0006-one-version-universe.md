# ADR-0006 — Use one ordered evidence-delta universe

**Status:** Accepted

## Decision

Canonical history is published as immutable `EvidenceDeltaBatch` roots. Graphs, search indexes,
subscriptions, replicas, checkpoints, and speculative branches consume that same ordered stream and
publish exact high-water marks.

## Rationale

Independent mutable caches and event buses create untraceable generation mixtures. A single version
universe allows snapshot-pinned queries, deterministic replay, incremental/full equivalence tests,
root-last replication, and exact stale-result reporting.

## Consequences

Every derived response reports authority and derived high-water marks. Compaction and migration
change representation through proof-carrying roots rather than rewriting history in place.
