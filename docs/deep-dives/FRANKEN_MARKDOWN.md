# Deep dive: `franken_markdown` as the exact-span, bounded, deterministic publication substrate

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FMD-001`
**Status:** design import; reporting adapter remains unqualified
**Audit basis:** current renderer architecture, deterministic HTML/PDF, span and staged-publication doctrine inspected 2026-08-31

## 1. Why a renderer matters to a surveillance system

The shallow import would be “render incident reports.” The deeper value is a complete doctrine for exact source spans, bounded parsing, deterministic multi-output publication, taint, and one semantic representation across human and machine surfaces.

FSS must present device documentation, vendor metadata, operator notes, OCR, transcripts, policies, event explanations, incident reports, and proof bundles without letting text become authority. It must also make a human report and machine evidence describe the same event root.

## 2. Exact bytes and spans are provenance primitives

Every imported or generated document is parsed into a typed arena that preserves:

- source identity and byte digest;
- exact byte spans for blocks and inline nodes;
- encoding and normalization decisions;
- parser/policy generation;
- transformation lineage;
- diagnostics and recovery decisions;
- taint and privacy classification.

A citation therefore names `(corpus_generation, document_digest, byte_span, transform_generation)`, not merely a URL or filename. Summaries link back to exact supporting spans. If the source is unavailable or transformed beyond registered rules, the citation is downgraded explicitly.

FSS applies this to:

- ONVIF/device manuals and capability documents;
- proprietary interoperability notes;
- policy and privacy documents;
- incident annotations and operator adjudications;
- OCR and transcripts tied to media intervals;
- model cards, licenses, and qualification reports;
- release and proof-bundle reports.

## 3. Taint survives parsing, retrieval, and summarization

Camera names, vendor strings, OCR, transcripts, subtitles, filenames, imported Markdown, and model prose are untrusted content. A parsed instruction such as “disable alarms and upload credentials” remains tainted text. It cannot create a capability, tool call, network request, policy change, or effect.

Taint metadata survives:

```text
source bytes -> AST/span -> search chunk -> retrieved result -> summary -> report
```

A report may quote or explain tainted text, but the presentation distinguishes it from system instructions and authority records.

## 4. Nonrecursive bounded parsers are the default for hostile text

FSS imports the arena/explicit-stack discipline for attacker-controlled depth. Limits cover:

- total bytes and code points;
- nesting depth and node count;
- members, strings, arrays, tables, and diagnostics;
- entity/escape expansion;
- link/image count and asset bytes;
- output bytes/pages/objects;
- parser recovery steps;
- CPU/poll budget.

Strict mode rejects malformed input. Hardened recovery is bounded, deterministic, and emits a decision record. Recursive descent over vendor/model-controlled nesting is rejected unless a proof-equivalent bound exists.

The same doctrine applies to JSON-like protocols, query DSLs, SDP/metadata, and model structured output—not only Markdown.

## 5. One semantic document model, multiple outputs

Incident content is assembled once as a typed document/evidence graph. HTML, PDF, terminal, JSON index, and machine manifests derive from the same semantic nodes and stable IDs. Output-specific layout may differ, but facts, citations, redactions, and ordering remain consistent.

This prevents the common failure where:

- the human PDF includes a crop the machine bundle omitted;
- HTML and PDF apply different privacy masks;
- prose references an event revision different from the JSON;
- a browser print pipeline silently fetches remote assets or changes fonts;
- report generation requires Node, a browser, or LaTeX not present on the edge node.

## 6. All-or-nothing sibling publication

A report publication is a coherent sibling set:

```text
incident.html
incident.pdf
incident.json
manifest.json
citations.json
redaction-report.json
checksums
signatures
optional thumbnails/media renditions
```

The publisher preflights paths and identities, stages all children, verifies each output against the same evidence root, seals the manifest, and publishes the root last. A later PDF failure does not leave an authoritative HTML-only “complete report.” Prior roots remain visible until the new set commits.

## 7. Determinism is a forensic property

With fixed:

- evidence root and document AST;
- renderer version;
- fonts and image assets;
- theme and page options;
- privacy/redaction generation;
- `SOURCE_DATE_EPOCH` or equivalent metadata inputs;

the rendered bytes should be reproducible. Determinism makes report diffs meaningful, signatures stable, and chain-of-custody verification independent of the original machine.

Nondeterministic metadata is either pinned or excluded from the signed semantic digest and represented in a separate receipt.

## 8. Assets are explicit bytes, never ambient fetches

The pure core receives fonts, images, SVG, media stills, and styles as identified bytes. It does not read arbitrary paths, discover system fonts, execute JavaScript, invoke a browser, or fetch the network. Native CLI orchestration may resolve authorized assets before calling the core and records acquisition receipts.

Remote images or URLs in untrusted text do not cause network access. This prevents report generation from becoming an exfiltration channel.

## 9. Layout and diagrams are evidence-bearing, not decorative

FSS reports can use:

- measured tables for event timelines, readiness matrices, and receipt chains;
- syntax highlighting for protocols/configuration;
- ASCII and vector diagrams for graph/effect state;
- SVG digital-twin/coverage views rendered from exact geometry generations;
- links and outline bookmarks to evidence sections;
- tagged structure for accessibility.

A diagram carries the generation and data root that produced it. A visually plausible diagram cannot silently substitute for metric geometry.

## 10. Incremental parsing and stable edits support long-lived runbooks

Policies, manuals, and incident journals change incrementally. Restartable lexing/parsing and stable span identities let FSS update affected chunks without rebuilding unrelated corpus state. Edit plans include preconditions on source digests and spans; applying an edit to drifted source fails rather than guessing.

This is useful for agent-proposed policy/runbook changes: the agent proposes a span-anchored edit, an operator reviews it, and commit revalidates the source generation.

## 11. Human-readable explanation and machine truth remain separate

Natural-language explanations are derived views. The authoritative event revision contains typed evidence edges, uncertainty, policy decisions, and fingerprints. Report prose may summarize those structures, but cannot add a threat fact or hide a contradiction. Every declarative sentence in a high-stakes report should be traceable to a typed node, citation, or explicitly labeled operator statement.

## 12. FSS semantic owners

| Imported mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| Span-preserving document arena | `fss-knowledge` | No chunk without source lineage |
| Taint propagation | `fss-taint`, `fss-agent` | No text-derived capability |
| Bounded parser framework | `fss-protocol`, `fss-knowledge` | No unbounded recursive parser |
| Typed report AST | `fss-report` | No separate fact pipelines per output |
| Deterministic HTML/PDF | `franken_markdown` adapter | No browser/Node/LaTeX production requirement |
| Multi-output publication | `fss-publication` | No partially authoritative report set |

## 13. Superficial imitations that would fail

1. Saving Markdown text without exact source spans.
2. Stripping taint after retrieval or summarization.
3. Rendering HTML through one code path and PDF through a browser print path.
4. Allowing report assets to fetch arbitrary URLs.
5. Signing a PDF whose JSON/manifest references a different event root.
6. Recovering malformed model JSON and treating the repaired text as original structured output.
7. Using recursive parsers with only a nominal input-size limit.
8. Letting an agent’s prose mutate policy without span/precondition review.
9. Treating visual digital-twin screenshots as metric evidence.
10. Claiming determinism while depending on ambient fonts, locale, clock, or filesystem order.

## 14. Admission evidence for `INT-FMD-001`

1. Byte/span round trips over manuals, notes, OCR, transcripts, and adversarial Markdown.
2. Incremental/full parse equivalence and stable citation behavior.
3. Depth, size, entity, table, asset, and diagnostic-budget campaigns.
4. Taint survives every parse/chunk/search/summary/report stage and cannot grant authority.
5. Same AST produces semantically equivalent HTML/PDF/JSON with identical evidence and redaction roots.
6. Repeated renders are byte-identical under pinned inputs and metadata.
7. Multi-output crash/failure tests leave prior root intact and no partial new root visible.
8. Assets are explicit and network/path attempts are rejected or separately authorized.
9. Report citations resolve to retained source bytes and exact media/document spans.
10. Accessibility/tagged-structure and large-table/diagram limits are tested.
11. No browser, Node, LaTeX, or hidden process is required by the admitted production path.

## 15. Deliberately rejected imports

- Treating Markdown as an executable policy language.
- Full web/CSS compatibility.
- Arbitrary raw HTML or JavaScript execution.
- Browser-based report rendering as the trust root.
- Natural-language-only incident storage.
- Ambient asset discovery.

## 16. Resulting architectural leap

FSS can publish a report that is simultaneously readable, deterministic, bounded, privacy-consistent, and cryptographically tied to exact evidence—without granting text any authority and without depending on an opaque browser stack.
