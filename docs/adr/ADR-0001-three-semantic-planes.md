# ADR-0001 — Separate authority, cognition, and effect planes

**Status:** Accepted for architecture bootstrap

## Decision

FSS separates:

- **authority:** immutable observations, identities, policies, receipts, and canonical state;
- **cognition:** tracks, embeddings, hypotheses, rankings, model outputs, and memories;
- **effects:** alerts, PTZ, retention, export, deletion, activation, and repair mutations.

Cognition may propose but cannot directly mutate authority or perform effects. Effects require
prepared intent, capability, precondition, idempotency identity, and receipt.

## Rationale

A model score is not a physical fact, and a provider ACK is not equivalent to an observed outcome.
Keeping the planes distinct preserves uncertainty, enables rollback/replay, and prevents model or
adapter code from becoming the trust root.

## Consequences

More explicit schemas and coordination are required. In exchange, failures remain classifiable and
agents can reason over evidence without ambient mutation authority.
