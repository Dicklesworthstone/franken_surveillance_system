# Franken-suite deep-dive index

These documents are normative design inputs for `franken_surveillance_system`. They separate **semantic imports** from physical crate adoption. A mechanism can be part of the FSS constitution before the sibling implementation is admitted; until its gate passes, FSS uses a simpler reference implementation or keeps the feature disabled.

| Project | Deep dive | Primary FSS contribution |
|---|---|---|
| Asupersync | [`ASUPERSYNC.md`](ASUPERSYNC.md) | ownership, authority, cancellation, obligations, deterministic lab, ATP |
| FrankenSQLite | [`FRANKENSQLITE.md`](FRANKENSQLITE.md) | one version axis, witnesses, SSI, commit combining, recovery |
| FrankenFS | [`FRANKENFS.md`](FRANKENFS.md) | custody states, root-last publication, repair, retrievability, deletion |
| Frankensearch/Quill | [`FRANKENSEARCH.md`](FRANKENSEARCH.md) | progressive retrieval, immutable generations, merge=concat, gauntlets |
| Franken Markdown | [`FRANKEN_MARKDOWN.md`](FRANKEN_MARKDOWN.md) | exact spans, taint, bounded parsing, deterministic reports |
| FrankenGraphDB | [`FRANKENGRAPHDB.md`](FRANKENGRAPHDB.md) | one delta universe, tiered relations, factorized joins, incremental views |
| FrankenNetworkX | [`FRANKEN_NETWORKX.md`](FRANKEN_NETWORKX.md) | certified graph algorithms, canonical choices, complexity witnesses |
| Dwarf Fortress MCP | [`DWARF_FORTRESS_MCP.md`](DWARF_FORTRESS_MCP.md) | honest control over a delayed, partially observed external world |
| FastMCP Rust | [`FASTMCP_RUST.md`](FASTMCP_RUST.md) | request-owned, capability-scoped agent presentation |
| Eidetic Engine CLI | [`EIDETIC_ENGINE_CLI.md`](EIDETIC_ENGINE_CLI.md) | evidence-backed operational memory and deterministic context packs |
| FrankenTorch | [`FRANKENTORCH.md`](FRANKENTORCH.md) | pure-Rust deterministic model execution and conformance |
| Doodlestein Self-Releaser | [`DOODLESTEIN_SELF_RELEASER.md`](DOODLESTEIN_SELF_RELEASER.md) | local clean-snapshot qualification and root-last releases |
| Adjacent projects | [`ADJACENT_FRANKEN_PROJECTS.md`](ADJACENT_FRANKEN_PROJECTS.md) | UI, audio, OCR, diagrams, simulation candidates |

The cross-project synthesis is [`../../FRANKENSTACK_DEEP_DIVE.md`](../../FRANKENSTACK_DEEP_DIVE.md). Machine-readable imports live in [`../../architecture/franken_imports.json`](../../architecture/franken_imports.json).
