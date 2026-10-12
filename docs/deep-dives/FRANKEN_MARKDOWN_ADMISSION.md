# FrankenMarkdown assimilation admission status (bead fss-x4a.27.54)

Companion to `FRANKEN_MARKDOWN.md`: the mechanism-by-mechanism record of
where each admitted structural-span / publication / robot-output concept
landed.

| Deep-dive mechanism | FSS landing site | Evidence | Status |
|---|---|---|---|
| §2 exact bytes + spans as provenance | source-linked spans throughout ingest (frame spans, packet spans, exact custody digests) | sensor capsule source-byte specs; `SensorSourceBytesSpec` binding identity to exact bytes | admitted |
| §3 taint survives parsing/retrieval/summarization | tainted-input handling in agent errors + untrusted-OCR cannot inject tool calls | GATE-110 criteria; AGENT_OPERATING_MODEL stale-alias taint rule; trigram guarded inputs in security lanes | admitted |
| §4 nonrecursive bounded parsers for hostile text | bounded parsers everywhere (H.264/H.265/MJPEG/matroska bounded, checked arithmetic) | malformed-media gauntlet; codec contract suites | admitted |
| §5 one semantic model, multiple outputs | typed payloads with canonical encoding → CLI/MCP/TUI/report transports | canonical-encoding discipline; transport-equivalence acceptance rows | admitted |
| §6 all-or-nothing sibling publication | human report + machine manifest publish atomically (PUB-EVIDENCE-001) | publication primitives row pinned (`publication_rows_contract.rs`) | admitted |
| §7 determinism as forensic property | deterministic replay everywhere (replay reproduces anchors; receipts byte-comparable) | replay contracts; receipt equivalence proofs (DSR vs direct) | admitted |
| §8 assets are explicit bytes, never ambient fetches | no runtime downloads (models/devices/config immutable generations; offline cargo) | netseal + offline lanes; DEP constitution | admitted |
| §9 layout/diagrams evidence-bearing | digest-domain registry (layout digests carry invariants) | DIGEST_DOMAINS registry (331 rows pinned) | admitted |
| §10 incremental parsing + stable edits | stable IDs never renumbered; supersession tombstones | stable-ID audit lane; tombstone contracts | admitted |
| §11 human explanation vs machine truth separate | AgentResponseEnvelope vs human docs; robot docs generated from machine registries | robot-docs generator + checker; envelope schemas | admitted |

## Verdict

All 10 mapped mechanisms admitted. The rejected-imports list (no general
markdown rendering pipeline in production; renderer stays a lab surface) is
intact — `franken_markdown` remains a gated family with zero closure
presence.
