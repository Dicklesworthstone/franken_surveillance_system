# ADR-0005 — Close the production universe around pure Rust and first-party substrate

**Status:** Accepted

## Decision

FSS production code consists of FSS workspace crates, Asupersync, admitted Franken-suite crates,
and a tiny machine-registered set of foundational exceptions. FSS crates inherit
`unsafe_code = "forbid"`. Tokio, alternate runtimes, Python/PyO3, FFmpeg/libav, OpenCV, ONNX
Runtime, libtorch, proprietary SDKs, generic graph/search/database engines, browser runtimes, and
dynamic plugin systems are not production dependencies.

## Rationale

FSS handles untrusted media, credentials, private imagery, physical-world decisions, and long-lived
evidence. Owning the dependency, execution, parser, persistence, and cancellation semantics is
necessary for deterministic replay, memory safety, local qualification, and honest failure modes.
Focused first-party implementations can also outperform general stacks by exploiting FSS's narrow
workloads without sacrificing safety.

## Consequences

Capabilities land only when a first-party Rust path passes its admission gate. Foreign tools remain
useful as pinned differential oracles. The repository carries a dependency constitution, exact
sibling revision closure, offline build rule, and no-runtime-download policy.
