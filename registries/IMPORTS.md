# Franken mechanism import registry

Each row names a mechanism, semantic owner, and admission gate. Family membership alone is not qualification.

| ID | Project | Mechanism | Owner | Gate | Status |
|---|---|---|---|---|---|
| `IMP-AS-ATP-001` | `asupersync` | Verified immutable object-graph transfer with path lifecycle, quarantine, journal, resume, repair symbols, and diagnostics | `fss-transfer` | `INT-AS-001` | `censused` |
| `IMP-AS-CANCEL-001` | `asupersync` | Request → drain → finalize cancellation with four-valued outcomes | `fss-runtime` | `INT-AS-001` | `censused` |
| `IMP-AS-LAB-001` | `asupersync` | Virtual time, replay, trace normalization, and DPOR-style exploration | `fss-lab` | `INT-AS-001` | `censused` |
| `IMP-AS-REGION-001` | `asupersync` | Region ownership and explicit Cx authority | `fss-runtime` | `INT-AS-001` | `censused` |
| `IMP-AS-SUBJECT-001` | `asupersync` | Semantic subject fabric with packet, authority, and reasoning service classes | `fss-subject` | `INT-AS-001` | `censused` |
| `IMP-FSQL-BOCPD-001` | `frankensqlite` | Bayesian online change-point detection for workload and sensor regimes | `fss-decision` | `INT-FSQL-001` | `censused` |
| `IMP-FSQL-COMBINE-001` | `frankensqlite` | Deterministic flat combining at narrow sequence/publication points | `fss-publication` | `INT-FSQL-001` | `censused` |
| `IMP-FSQL-MVCC-001` | `frankensqlite` | Multi-version canonical ledger with semantic read/write witnesses and SSI dangerous-structure detection | `fss-ledger` | `INT-FSQL-001` | `censused` |
| `IMP-FFS-PUBLISH-001` | `frankenfs` | Staged → visible → durable → protected publication lattice and root-last activation | `fss-publication` | `INT-FFS-001` | `censused` |
| `IMP-FFS-REPAIR-001` | `frankenfs` | Doctor → sealed repair plan → revalidate → apply workflow | `fss-doctor` | `INT-FFS-001` | `censused` |
| `IMP-FFS-RQ-001` | `frankenfs` | RaptorQ protection, refresh policy, retrievability evidence, and decode drills | `fss-custody` | `INT-FFS-001` | `censused` |
| `IMP-FSEARCH-GAUNTLET-001` | `frankensearch` | Pinned-oracle divergence ledger, model-space identity, same-binary semantic receipts | `fss-gauntlet` | `INT-FSEARCH-001` | `censused` |
| `IMP-FSEARCH-PROGRESS-001` | `frankensearch` | Progressive lexical/semantic retrieval over immutable pinned generations | `fss-search` | `INT-FSEARCH-001` | `censused` |
| `IMP-FSEARCH-QUILL-001` | `frankensearch` | Searchable delta, durable seal, globally ordered ID ranges, merge=concat, and columnar sort-based ingest | `fss-search` | `INT-FSEARCH-001` | `censused` |
| `IMP-FMD-PUBLISH-001` | `franken_markdown` | One parsed representation with deterministic multi-output publication and sibling rollback | `fss-report` | `INT-FMD-001` | `censused` |
| `IMP-FMD-SPAN-001` | `franken_markdown` | Exact source spans, taint propagation, bounded explicit-stack parsing | `fss-knowledge` | `INT-FMD-001` | `censused` |
| `IMP-FGDB-BRANCH-001` | `frankengraphdb` | O(1) branches, semantic intent merge, plan certificates, and capability-before-expansion | `fss-branch` | `INT-FGDB-001` | `censused` |
| `IMP-FGDB-LOOM-001` | `frankengraphdb` | Factorized and worst-case-optimal FreeJoin execution over graph-shaped relations | `fss-graph-query` | `INT-FGDB-001` | `censused` |
| `IMP-FGDB-RIPPLE-001` | `frankengraphdb` | DBSP-style Z-set incremental maintenance for views, subscriptions, statistics, and analytics | `fss-incremental` | `INT-FGDB-001` | `censused` |
| `IMP-FGDB-STRATA-001` | `frankengraphdb` | Temperature-tiered graph storage: inline micro-adjacency, sorted deltas, sealed compressed runs, archived anchors | `fss-graph-store` | `INT-FGDB-001` | `censused` |
| `IMP-FGDB-VERSION-001` | `frankengraphdb` | One version universe for history, replication, subscriptions, branches, and derived high-water marks | `fss-chronicle` | `INT-FGDB-001` | `censused` |
| `IMP-FNX-ALG-001` | `franken_networkx` | Broad graph algorithm families for connectivity, flow, matching, centrality, temporal and structural reasoning | `fss-graph-algorithms` | `INT-FNX-001` | `censused` |
| `IMP-FNX-CGSE-001` | `franken_networkx` | CGSE deterministic tie-break policies and observable-behavior parity | `fss-graph-algorithms` | `INT-FNX-001` | `censused` |
| `IMP-FNX-WITNESS-001` | `franken_networkx` | ComplexityWitness and decision-path ledger per algorithm call | `fss-graph-algorithms` | `INT-FNX-001` | `censused` |
| `IMP-DFMCP-ANCHOR-001` | `dwarf_fortress_mcp` | Evidence anchors, resumable hash-linked deltas, negative-domain witnesses, and token-economical views | `fss-api` | `INT-DFMCP-001` | `censused` |
| `IMP-DFMCP-EFFECT-001` | `dwarf_fortress_mcp` | Prepared semantic intents, delayed external-effect truth, obligations, reconciliation, and Indeterminate outcomes | `fss-effect` | `INT-DFMCP-001` | `censused` |
| `IMP-FMCP-BOUNDARY-001` | `fastmcp_rust` | Bounded capability-scoped MCP presentation with request-owned child work | `fss-mcp` | `INT-FMCP-001` | `censused` |
| `IMP-FMCP-REQUEST-001` | `fastmcp_rust` | One request-owned region with bounded cancellation, progress, output commitment, and cleanup semantics | `fss-mcp` | `INT-FMCP-001` | `censused` |
| `IMP-FMCP-SCHEMA-001` | `fastmcp_rust` | Registry-derived bounded semantic tools/resources/prompts with stable schemas, errors, continuation anchors, and taint handling | `fss-api` | `INT-FMCP-002` | `censused` |
| `IMP-EE-CURATION-001` | `eidetic_engine_cli` | Immutable proposal/review/apply curation, outcome provenance, revival conditions, hygiene scoring, and harmful-feedback anti-pattern inversion | `fss-memory` | `INT-EE-002` | `censused` |
| `IMP-EE-MEMORY-001` | `eidetic_engine_cli` | Provenance-bearing advisory memory, deterministic context packs, confidence decay, trauma guard, and anti-pattern inversion | `fss-memory` | `INT-EE-001` | `censused` |
| `IMP-FTORCH-001` | `frankentorch` | Canonical first-party tensor/model package identity with typed shapes, dtypes, layouts, aliases, preprocessing, and operator graph | `fss-model-registry` | `INT-FT-001` | `censused` |
| `IMP-FTORCH-KERNEL-001` | `frankentorch` | Scalar semantic kernels with safe tiled, fused, SIMD, parallel, and quantized implementations admitted by differential envelopes | `fss-kernel-cpu` | `INT-FT-003` | `censused` |
| `IMP-FTORCH-PLAN-001` | `frankentorch` | Frozen shape-specialized execution plan, liveness-based scratch arena, and static backend dispatch | `fss-model-runtime` | `INT-FT-002` | `censused` |
| `IMP-FTORCH-RECEIPT-001` | `frankentorch` | Receipt-bearing invocation and package-generation separation for lowering, packing, quantization, calibration, and accelerator variants | `fss-model-runtime` | `INT-FT-004` | `censused` |
| `IMP-DSR-001` | `doodlestein_self_releaser` | Local execution of workflow YAML, clean source snapshots, exact sibling closure, resumable target matrix, root-last release publication, and download verification | `fss-release` | `INT-DSR-001` | `censused` |
| `IMP-DSR-CUSTODY-001` | `doodlestein_self_releaser` | Exact asset enumeration, signing separation, SBOM/provenance/source closure, upload, download, and byte-for-byte verification | `fss-release` | `INT-DSR-003` | `censused` |
| `IMP-DSR-MATRIX-001` | `doodlestein_self_releaser` | Controlled native-host target matrix with resumable retained artifacts but no authoritative partial release root | `fss-release` | `INT-DSR-002` | `censused` |
| `IMP-FSEARCH-CONTEXT-001` | `frankensearch` | progressive retrieval as task-relative context acquisition with immutable generation, score ledger, stop reason, and certified absence boundaries | `fss-context-pack` | `GATE-115` | `planned` |
| `IMP-FGDB-AGENT-001` | `frankengraphdb` | branch-per-agent task and decision graphs over one version universe with capability projection before expansion | `fss-agent-session` | `GATE-115` | `planned` |
| `IMP-FNX-EVIDENCE-001` | `franken_networkx` | canonical minimal evidence subgraphs using dominators, cuts, causal ancestors, submodular coverage, and complexity witnesses | `fss-context-pack` | `GATE-115` | `planned` |
| `IMP-DFMCP-COCKPIT-001` | `dwarf_fortress_mcp` | semantic transactional control cockpit for a partially observed changing world with plans, obligations, indeterminate effects, and compact attention | `fss-agent-core` | `GATE-115` | `planned` |
| `IMP-FMCP-COGNITIVE-001` | `fastmcp_rust` | one bounded request-owned semantic operation registry projected identically across CLI and MCP with transport-specific qualification | `fss-mcp` | `GATE-115` | `planned` |
| `IMP-EE-SESSION-001` | `eidetic_engine_cli` | deterministic context packs, typed procedural memory, outcome attribution, trauma guard, revival, and resumable agent handoff | `fss-learning` | `GATE-115` | `planned` |
| `IMP-AS-AGENT-001` | `asupersync` | region-owned AgentSession and durable-work supervision with explicit Cx authority, budgets, cancellation drain, continuations, and obligation closure | `fss-agent-session` | `GATE-115` | `planned` |
| `IMP-FSQL-AGENT-001` | `frankensqlite` | multi-version mission, workspace, investigation, finding, plan, episode, and handoff revisions with semantic witnesses and deterministic publication | `fss-agent-session` | `GATE-115` | `planned` |
| `IMP-FMD-ROBOT-001` | `franken_markdown` | one span-preserving semantic source for robot documentation, human reports, schema explanations, examples, and deterministic multi-output publication | `fss-report` | `GATE-115` | `planned` |
