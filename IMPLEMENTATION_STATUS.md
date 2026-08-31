# Implementation status

**As of:** 2026-08-31
**Repository phase:** architecture constitution
**Aggregate readiness:** design-only; no operational surveillance functionality is qualified

This file is the public claim boundary. Source presence, a schema, a type, a CLI command, a passing
unit test, or a successful one-off device experiment is not aggregate support.

The current constitutional inventory contains **116 unique hard invariants, 47 admitted-or-proposed
Franken mechanism imports, 27 registered graph algorithms, 13 publication primitives, 11 agent
abstraction layers, 14 public agent operations, 8 registered agent views, 15 local qualification
lanes, and 49 JSON Schema files**. Those numbers describe design coverage and machine
cross-checking, not operational readiness.

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
| Agent semantic protocol, operation/view registries, and epistemic types | specified in depth | machine registries + schemas | no | policy cross-check only | architecture artifacts present; not implemented |
| ContractBasis and universal request/response envelopes | specified in depth | schemas + registry cross-checks | no | policy cross-check only | architecture artifacts present; not implemented |
| SituationCapsule/Frame, WorldEnvelope, context packs, and semantic compression | specified in depth | schemas only | no | no | not implemented |
| Evidence–possibility–control and robust/conditional action classification | specified in depth | schemas + decision/test/SLO registries | no | no | not implemented |
| Investigations, hypotheses, VOI, affordances, and contingent control plans | specified in depth | schemas + decision registries | no | no | not implemented |
| Multi-agent work claims/findings, handoff/resume, and accretive learning | specified in depth | schemas only | no | no | not implemented |
| Rust API/CLI/MCP/TUI/report presentation | specified | no | no | no | not implemented |
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

The repository policy validator passed in the artifact environment over **66 JSON files, 8 TOML
files, 1,076 unique stable identifiers, 116 invariants, 47 mechanism imports, 27 graph algorithms,
13 publication primitives, 11 agent abstraction layers, 14 public agent operations, 8 registered
agent views, and 15 local qualification lanes**. All 49 JSON Schema files passed Draft 2020-12
meta-schema validation, all internal schema references resolved, all repository Markdown links
resolved, the 199-entry repository integrity manifest matched every included file, the eight root
constitutional documents matched their `docs/` mirrors byte-for-byte, the
static dependency audit reported no policy violations, and the deterministic release-artifact
custody test reproduced byte-identical Linux and Windows packages while verifying the single
common-asset authority split.

Those checks establish internal architectural consistency only. They do not demonstrate that an
agent can yet orient, investigate, choose an affordance, prepare or commit a plan, reconcile an
indeterminate effect, hand work to another agent, or improve from an ExperienceCapsule.
`QL-AGENT-001` and `GATE-115` remain entirely unearned until executable task-level reference,
fault, compression, capability, handoff, multi-agent, and accretion evidence exists.

A Rust toolchain was not available in that environment, so `cargo metadata`, `cargo fmt`, `cargo
check`, Clippy, and `cargo test` could not be run there. The code is intentionally dependency-free
at this skeleton stage and the repository-owned local/portable qualifiers contain the complete
locked/offline commands, but Rust build qualification remains pending until those commands pass on
`nightly-2026-08-31` through a native DSR lane. GitHub-hosted execution is supplementary and is not
required release evidence.
