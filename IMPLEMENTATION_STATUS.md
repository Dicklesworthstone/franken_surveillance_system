# Implementation status

**As of:** 2026-08-31
**Repository phase:** architecture constitution
**Aggregate readiness:** design-only; no operational surveillance functionality is qualified

This file is the public claim boundary. Source presence, a schema, a type, a CLI command, a passing
unit test, or a successful one-off device experiment is not aggregate support.

The current constitutional inventory contains **82 unique hard invariants, 38 admitted-or-proposed
Franken mechanism imports, 27 registered graph algorithms, 10 publication primitives, 14 local
qualification lanes, and 17 versioned interchange schemas**. Those numbers describe design
coverage and machine cross-checking, not operational readiness.

## Dimension matrix

| Surface | Contract | Reference | Implementation | Qualification | Public claim |
|---|---:|---:|---:|---:|---|
| Semantic IDs, time intervals, event states | yes | partial Rust skeleton | partial | no | contract skeleton only |
| Machine-readable registries and schemas | yes | yes | yes | policy parser only | architecture artifacts present |
| Deterministic replay adapter | specified | no | no | no | not implemented |
| UVC/UAC acquisition | specified | no | no | no | not implemented |
| RTSP acquisition | specified | no | no | no | not implemented |
| ONVIF Profile T/M client | specified | no | no | no | not implemented |
| Wyze Cam v4 lab adapter | specified | no | no | no | research target only |
| AOSU P1 Max lab adapter | specified | no | no | no | research target only |
| DJI Flip capture bridge | specified | no | no | no | research target only |
| Pure-Rust packet/container/codec/media kernel | specified in depth | no | no | no | not implemented |
| Live proxy | specified | no | no | no | not implemented |
| Canonical ledger | specified | no | no | no | not implemented |
| Local object spool | specified | no | no | no | not implemented |
| B2/R2 archive | specified | no | no | no | not implemented |
| Pure-Rust model package/import/runtime | specified in depth | no | no | no | not implemented |
| Detection/tracking/fusion | specified | no | no | no | not implemented |
| Calibration/digital twin | specified | no | no | no | not implemented |
| Alert policy/delivery | specified | no | no | no | not implemented |
| One version universe and MVCC witness ledger | specified in depth | schema only | no | no | not implemented |
| ATP transfer/object graph and retrievability | specified in depth | schemas only | no | no | not implemented |
| Certified graph algorithms/complexity witnesses | specified in depth | registry only | no | no | not implemented |
| Search/memory/graph projections | specified in depth | no | no | no | not implemented |
| Local DSR qualification/release custody | specified in depth | policy scripts only | partial | no native release receipt | not qualified |
| MCP/agent surface | specified | no | no | no | not implemented |
| Human operations UI | conceptual | no | no | no | not implemented |

## Why the skeleton exists

The first code is not a fake camera demo. It freezes load-bearing distinctions that become very
expensive to recover later:

- capture time is uncertain;
- observations, model hypotheses, and effects have different authority;
- acquisition acceptance is not frame continuity;
- event detection is not corroboration;
- corroboration is not policy adjudication;
- adjudication is not delivered alert;
- model scores need a generation and calibration identity;
- public readiness is multidimensional.

## Promotion rule

A row may move from `implemented` to `qualified` only when all applicable readiness dimensions in
`architecture/readiness_dimensions.json` have retained evidence. The proof bundle must name the
exact source revision, toolchain, platform, device/firmware/app tuple, model generations, fixture
roots, configuration, seeds, raw measurements, failures, and reproduction commands.

## Known qualification gap in this generated snapshot

The repository policy validator passed in the artifact environment over **29 JSON files, 8 TOML
files, 809 unique stable identifiers, 82 invariants, 38 mechanism imports, 27 graph algorithms, 10
publication primitives, and 14 local qualification lanes**. All 17 Draft 2020-12 schemas passed
meta-schema validation, all internal schema references resolved, all repository Markdown links
resolved, the five root constitutional documents matched their `docs/` mirrors byte-for-byte, and
the static dependency audit reported no policy violations.

A Rust toolchain was not available in that environment, so `cargo metadata`, `cargo fmt`, `cargo
check`, Clippy, and `cargo test` could not be run there. The code is intentionally dependency-free
at this skeleton stage and the repository-owned local/portable qualifiers contain the complete
locked/offline commands, but Rust build qualification remains pending until those commands pass on
`nightly-2026-08-31` through a native DSR lane. GitHub-hosted execution is supplementary and is not
required release evidence.
