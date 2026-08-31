# Source census

**Research cut:** 2026-08-30

This repository was designed after direct inspection of the following user-owned projects and
planning documents.

## Franken projects

- [`asupersync`](https://github.com/Dicklesworthstone/asupersync): README, `asupersync_plan_v4.md`,
  dependency-replacement and RABS plans, runtime/formal architecture surfaces.
- [`frankensqlite`](https://github.com/Dicklesworthstone/frankensqlite): README, architecture,
  compatibility/readiness boundaries, MVCC/recovery claims.
- [`frankenfs`](https://github.com/Dicklesworthstone/frankenfs): README and
  `COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md`.
- [`frankensearch`](https://github.com/Dicklesworthstone/frankensearch): README and
  `COMPREHENSIVE_PLAN_FOR_THE_QUILL_LEXICAL_ENGINE.md`.
- [`franken_markdown`](https://github.com/Dicklesworthstone/franken_markdown): README, deterministic
  render/agent/qualification surfaces.
- [`frankengraphdb`](https://github.com/Dicklesworthstone/frankengraphdb):
  `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGRAPHDB.md`, especially the version universe, typed
  claim system, workstreams, gates, and operation-cost registry.
- [`dwarf_fortress_mcp`](https://github.com/Dicklesworthstone/dwarf_fortress_mcp):
  `FRANKENSTACK_DEEP_DIVE.md`, `COMPREHENSIVE_PLAN_FOR_DWARF_FORTRESS_MCP.md`, README, registries,
  schemas, and architecture files.
- [`fastmcp_rust`](https://github.com/Dicklesworthstone/fastmcp_rust): README,
  `COMPREHENSIVE_PLAN_TO_SUPPORT_MCP_2026-07-28_SPEC_IN_FASTMCP_RUST.md`, qualification boundaries,
  and agent/runtime contracts.
- [`eidetic_engine_cli`](https://github.com/Dicklesworthstone/eidetic_engine_cli): README and
  `COMPREHENSIVE_PLAN.md`, including local-first memory, evidence, feedback, graph/search, and
  reality-check bridge plans.

## External primary sources

See [`REFERENCES.md`](REFERENCES.md). External facts are inputs to dated registries, not eternal
source constants. Device interfaces, model licenses, SDK support, provider pricing, and standards
must be re-verified at qualification time.

## Research limitations

- No live devices, accounts, packet captures, or vendor credentials were available in this design
  pass.
- No model weights were downloaded or benchmarked.
- No Rust toolchain was available in the artifact environment; the generated Rust skeleton was
  statically reviewed and policy-validated but not compiled there.
- Proprietary device conclusions are limited to public owner-facing documentation and current
  official SDK/product listings. “No public contract found” is not proof that no private/local
  method exists.
- The plan intentionally treats rapidly changing model rankings as hypotheses to evaluate rather
  than facts to freeze.
