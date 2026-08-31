# ADR-0002 — Isolate foreign codecs, vendor integrations, and model runtimes in boundary processes

**Status:** Superseded by [`ADR-0005`](ADR-0005-pure-rust-production-universe.md) and [`ADR-0010`](ADR-0010-foreign-runtimes-are-lab-oracles.md)

## Historical decision

The bootstrap architecture proposed running native codec stacks, vendor SDK/app automation,
Python/CUDA model runtimes, and broad provider clients outside the authoritative safe-Rust core,
communicating through versioned bounded local protocols.

## Why this was insufficient

Process isolation narrows crash and authority propagation, but it does not make the shipping system
pure Rust or close the semantic/dependency universe. A required foreign service still imports a
second runtime, memory-safety model, scheduler, parser stack, supply chain, update channel, and
model/media interpretation into production.

## Replacement

Production FSS media, model, graph, archive, and orchestration paths are first-party safe Rust.
Foreign tools can remain pinned, isolated differential oracles in qualification laboratories. A
missing first-party implementation means the capability remains unsupported or fails closed; it
does not silently activate a foreign production fallback.
