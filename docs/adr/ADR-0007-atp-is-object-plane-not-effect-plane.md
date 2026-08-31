# ADR-0007 — ATP moves immutable object graphs, never mutation authority

**Status:** Accepted

## Decision

Asupersync ATP is the bulk movement plane for media, checkpoints, evidence bundles, model packages,
graph/search/calibration/twin generations, replay corpora, and release artifacts. Alerts, PTZ,
deletion, retention changes, activation, and any future physical control use separate semantic
effect protocols with idempotency, fencing, observation, and reconciliation.

## Rationale

Bulk transfer is resumable, repairable, and eventually delivered; consequential effects require
precise authority and outcome semantics. Conflating the two makes retries unsafe and transfer
acceptance look like physical completion.

## Consequences

ATP receipts prove object closure, post-repair digests, root publication, and retrievability. They
cannot authorize an effect.
