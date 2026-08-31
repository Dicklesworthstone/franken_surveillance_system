# ADR-0002 — Isolate codecs, vendor integrations, and model runtimes in boundary processes

**Status:** Accepted for architecture bootstrap

## Decision

Native codec stacks, vendor SDK/app automation, Python/CUDA model runtimes, and provider clients do
not execute inside the authoritative safe-Rust core. They communicate through versioned bounded
local protocols and publish staged outputs that the core validates before commitment.

## Rationale

These ecosystems are necessary but large, mutable, and failure-prone. Process isolation keeps
crashes, malformed outputs, unsafe code, licenses, and dependency churn outside the semantic and
security core.

## Consequences

The project must own supervision, cancellation, transport schemas, resource limits, and copy costs.
Those costs are measured in the operation-cost registry rather than hidden.
