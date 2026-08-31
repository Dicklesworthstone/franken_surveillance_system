# Source census

**Architecture research cut:** 2026-08-31
**External device/model/pricing snapshot:** 2026-08-30

This repository was produced by a second-pass, mechanism-level study of the user-owned projects
below. The audit did not ask merely whether a sibling had a thematically similar feature. For each
candidate transplant it asked:

1. What exact algorithm, state machine, data structure, or proof surface is load-bearing?
2. Which FSS crate owns its semantics?
3. What invariant does it establish and where is its soundness frontier?
4. What superficial imitation would preserve the name but lose the guarantee?
5. What deterministic reference oracle, fault campaign, and retained receipt admit it?
6. How does FSS fail closed or degrade before the sibling implementation is qualified?

The answers are recorded in [`FRANKENSTACK_DEEP_DIVE.md`](../FRANKENSTACK_DEEP_DIVE.md), the
[`deep-dives/`](deep-dives/INDEX.md) directory, `architecture/franken_imports.json`, and the focused
constitutional documents at the repository root.

## Asupersync

Inspected surfaces include `README.md`, `asupersync_plan_v4.md`,
`asupersync_v4_formal_semantics.md`, `ATP_DOD_CHECKLIST.md`, the RABS and dependency-replacement
plans, runtime/lab/trace modules, and ATP transfer, manifest, journal, object-graph, path-selection,
repair, and proof-lane surfaces.

Material imports include region-owned work, explicit `Cx` authority, outcome severity, obligations,
reserve/commit effects, request→drain→finalize cancellation, virtual time, schedule exploration,
trace equivalence and normalization, deterministic fault injection, and ATP’s verified immutable
object graph with resumable journals, repair symbols, multipath delivery, and root-last commit.
ATP is explicitly not an RPC synonym and never carries mutation authority.

## FrankenSQLite

Inspected surfaces include `README.md`, workspace layering, MVCC/SSI contracts, pager/WAL and
recovery boundaries, conformance harnesses, typed page/transaction identities, current readiness
qualifications, and the comprehensive specification retained in the FrankenFS research corpus.

Material imports include a single ordered version axis, snapshot-pinned reads, positive and
negative hierarchical witnesses, deterministic commit combining, dangerous-structure detection,
semantic rather than byte-level merge, crash-point classification, compatibility-oracle
comparison, and the doctrine that storage source presence is not persistence qualification.

## FrankenFS

Inspected surfaces include `README.md`, `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`, feature/readiness
accounting, writeback-cache state machines, RaptorQ repair, scrub/retrievability evidence,
rooted-capability filesystem effects, and doctor→sealed-plan→apply workflows.

Material imports include explicit staged/visible/durable/replicated/retrievable states, coherent
multi-artifact publication, generation fences, unified repair serialization, RaptorQ only where a
measured recovery model justifies it, proof bundles, crash matrices, path-attack fixtures, and
machine-separated implementation versus operational readiness.

## Frankensearch and Quill

Inspected surfaces include `README.md`, `COMPREHENSIVE_PLAN_FOR_THE_QUILL_LEXICAL_ENGINE.md`,
immutable index generations, progressive search, FSVI format discipline, searchable deltas,
conformance oracles, performance ledgers, model identity, and durability/protection modules.

Material imports include cheap-first progressive retrieval, exact generation pinning, lexical /
structured / graph / semantic stage separation, absence certificates, merge=concat through ordered
absolute IDs, columnar sort-based ingest, visibility distinct from durability, deterministic top-k,
score ledgers, held-out differential gauntlets, and fail-closed model-space identity.

## Franken Markdown

Inspected surfaces include `README.md`, parser/AST, deterministic HTML/PDF output, batch
orchestration, exact spans, bounded diagnostics, staged multi-output publication, WASM parity, and
agent-facing capability/doctor contracts.

Material imports include exact byte/span provenance, bounded nonrecursive parsing, taint
preservation, one semantic document source for human and machine reports, deterministic rendering,
and all-or-nothing sibling publication. Text can inform cognition but never grant capability.

## FrankenGraphDB

Inspected surfaces include the comprehensive design plan, workspace/crate topology, calibration,
e-process, query, graph-storage, incremental-view, branch, and proof-related modules and registries.

Material imports include one append-only version universe, temperature-tiered adjacency, snapshot
views, factorized and worst-case-aware joins, incremental retract/add maintenance, branch-per-agent
speculation, planner-enforced capability scope, typed claims, operation-cost rows, Decision Cards,
reference semantics, and acceptance gates rather than optimistic status prose.

## FrankenNetworkX

Inspected surfaces include `README.md`, `AGENTS.md`, the algorithm catalog, CGSE policy/witness
surfaces, conformance and parity ledgers, resistance-distance fixtures, complexity instrumentation,
strict/hardened parsing modes, RaptorQ-protected artifacts, and current implementation topology.

Material imports include deterministic insertion/iteration order, explicit canonical tie-breaks,
immutable snapshot inputs, decision-path digests, complexity witnesses, exactness classes,
adversarial graph families, differential reference tests, and a large operational algorithm atlas:
connectivity, cuts, dominators, temporal reachability, matching, flow, facility location, PPR,
community/shared-failure analysis, deletion closure, sensor placement, and wait-for diagnostics.

## FrankenTorch

Inspected surfaces include `README.md`, the comprehensive V1 specification, tensor/autograd/device/
dispatch/kernel/serialization/runtime/conformance layering, deterministic autograd evidence, static
operator registration, CPU kernels, package artifacts, differential oracles, and reliability
budgets.

Material imports include typed shape/dtype/layout/device contracts, frozen first-party operator IR,
static lowering, scalar reference kernels, safe optimized kernels admitted only by equivalence,
deterministic memory plans, canonical model packages, execution receipts, and strict separation of
production Rust execution from PyTorch/ONNX/CUDA laboratory oracles.

## Dwarf Fortress MCP

Inspected surfaces include `FRANKENSTACK_DEEP_DIVE.md`,
`COMPREHENSIVE_PLAN_FOR_DWARF_FORTRESS_MCP.md`, README, architecture registries, schemas, bridge
contracts, FastMCP integration, implementation status, and release doctrine.

This is the closest semantic analogue. Material imports include canonical anchors and resumable
deltas for an externally changing world, negative-domain witnesses, intent compilation, honest
operation states, durable obligations, effect/ledger separation, token-bounded semantic views,
compatibility generations, three-plane authority/cognition/effect separation, and local release
qualification.

## FastMCP Rust

Inspected surfaces include `README.md`, the MCP 2026-07-28 plan, qualification boundaries,
request/cancellation/session/cache/authentication contracts, task ownership, subprocess cleanup,
feature parity, and agent instructions.

Material imports include request-owned child work, capability-scoped tools/resources/prompts,
bounded wire structures, four-valued outcomes, application-owned durable tasks, explicit protocol
era negotiation, authority-preserving cache keys, and the rule that MCP is a presentation plane,
not a source of canonical semantics or ambient vendor/model access.

## Eidetic Engine CLI

Inspected surfaces include `README.md`, `COMPREHENSIVE_PLAN.md`, reality-check bridge plans,
retrieval/graph/context-pack surfaces, memory lifecycle, feedback, trauma guard, curation, provenance,
and local-first CLI contracts.

Material imports include immutable evidence-linked operational memory, typed facts/rules/failures/
anti-patterns, confidence decay, harmful-feedback demotion, deterministic context packs,
explainable hybrid retrieval, explicit curation proposals, and the prohibition against memory
rewriting canonical event, privacy, model, or effect truth.

## Doodlestein Self-Releaser

Inspected surfaces include `README.md`, `AGENTS.md`, `SKILL.md`, `docs/ARTIFACT_NAMING.md`,
`docs/CLI_CONTRACT.md`, the Rust repository template, act/native host orchestration, build-state,
host-selection, signing, SBOM, SLSA, release verification, canary, and exact-asset contracts.

Material imports include workflow YAML as a portable job graph, repository-owned qualifier scripts,
clean immutable source snapshots, exact sibling revision closure, native Linux/macOS/Windows lanes,
resumable target artifacts that remain unblessed, disk-backed staging, exact asset enumeration,
checksums/signatures/SBOM/provenance, tag-policy verification, post-upload download verification, and
aggregate-root-last publication. GitHub-hosted Actions are supplementary, never release authority.

## Adjacent Franken-suite candidates

The census also records possible future use of Frankentui, audio/speech, OCR, simulation,
diagramming, networking, and other owned projects. They are not admitted merely because they are
owned. Each requires a concrete semantic owner, replacement prohibition, reference oracle, cost
row, and integration gate before entering the production closure.

## External primary sources

See [`REFERENCES.md`](REFERENCES.md). External facts are inputs to dated registries, not eternal
source constants. Device interfaces, model licenses, SDK support, provider pricing, and standards
must be re-verified at qualification time.

## Research limitations

- No live devices, accounts, packet captures, or vendor credentials were available in this design
  pass.
- No model weights were downloaded or benchmarked.
- No Rust toolchain was available in the artifact environment; the Rust skeleton and qualification
  scripts were statically inspected and policy-validated but not compiled there.
- Proprietary-device conclusions are limited to public owner-facing material. “No public contract
  found” is not proof that no private/local method exists.
- The comprehensive plans are ambitious target contracts. FSS imports a mechanism only with a
  named soundness frontier and admission gate; source presence in a sibling is not proof that the
  mechanism is production-qualified there or here.
- Rapidly changing model rankings remain hypotheses to test against FSS’s sealed property-security
  corpus, not facts frozen into source.
