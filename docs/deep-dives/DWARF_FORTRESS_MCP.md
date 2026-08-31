# Deep dive: `dwarf_fortress_mcp` as the closest semantic-control-plane analogue

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-DFMCP-001`
**Status:** architecture doctrine imported
**Audit basis:** comprehensive plan, Franken-stack deep dive, architecture registries, effect/obligation and local-qualification doctrine inspected 2026-08-31

## 1. Why the analogy is deeper than “agents control a complex system”

Both Dwarf Fortress and a real property are externally changing, partially observed worlds. Actions may be accepted now, become visible later, fail silently, or have ambiguous completion. Sensor information is delayed, version-sensitive, and incomplete. Long-horizon agents need compact semantic state, safe plans, durable obligations, and later proof—not thousands of low-level commands.

The closest transfer is therefore the semantic control-plane shape:

```text
canonical multi-version world history
+ compact evidence-bearing projections
+ immutable intent compilation
+ witnessed optimistic validation
+ narrow external-effect bridge
+ durable obligations and reconciliation
+ capability-scoped agent interface
```

## 2. Franken substrate contract

The DFMCP deep dive imposes the strongest import rule in the fleet. Every dependency/mechanism needs:

1. semantic owner;
2. replacement prohibition;
3. deterministic reference model;
4. failure boundary;
5. admission gate and retained evidence.

FSS adopts this as constitutional. Listing a sibling in Cargo.toml is not integration. A mechanism remains behind a reference adapter until its gate passes.

## 3. Three planes remain non-negotiable

### Authority

What FSS observed, which versions existed, what policy/capability was active, what intent committed, what effect receipt exists, and what object root is published.

### Cognition

Tracks, embeddings, graph projections, VLM outputs, rankings, routines, attention, and counterfactual branches derived from named authority anchors.

### Effect

Camera configuration, alerts, exports, deletion, repair, activation, and any future actuator. Narrow, fenced, idempotent/reconciled, and unable to redefine canonical semantics.

No model output crosses directly from cognition to effect.

## 4. Multi-version world and observation capsules

FSS’s `EvidenceDeltaBatch` and sensor capsules mirror the observation-capsule doctrine. Each batch is an ordered, resumable, hash-anchored change set. Agents pin an anchor and ask for deltas from it rather than repeatedly dumping the world.

Every derived graph/search generation names the consumed high-water mark. A query that needs exact current state waits/recomputes or returns stale/uncertified; it cannot silently mix generations.

## 5. Every negative read is witnessed

The DFMCP principle “no hostile unit exists in this region” maps directly to “no person/event exists in this protected zone.” FSS records the observed domain, coverage, sensor health, time interval, model floor, and exclusions. Absence without domain coverage is `unknown`, not false.

This changes effect safety. A plan to suppress an alert, move a PTZ camera, or delete apparently irrelevant media conflicts when new evidence enters the negative domain or coverage degrades.

## 6. Plans are semantic transactions over an externally mutating world

An agent submits intent such as:

- investigate this event under 2,000 tokens and 300 ms of model budget;
- prepare an alert using redaction profile P;
- reorient PTZ camera within bounds to inspect zone Z;
- activate calibration/model generation G;
- delete all data reachable from scope S except legal holds;
- export a privacy-minimized incident bundle.

The server compiles intent into a deterministic plan with:

- pinned anchor and read/write witnesses;
- capabilities, leases, fences, and budgets;
- exact effect steps and preconditions;
- checkpoints and obligations;
- expected postconditions and verification;
- compensation/reconciliation paths;
- decision fingerprint and cost estimate.

Commit revalidates against the current anchor. The external bridge performs a final bounded check. The physical/provider effect is then observed and proved separately from ledger commit.

## 7. External effect states are not collapsed

FSS distinguishes:

```text
intent durable
prepared
committed for dispatch
request transmitted
adapter/provider accepted
physical/provider effect observed
terminal postcondition verified
failed / cancelled / indeterminate
```

For camera controls, a vendor ACK is not proof the lens moved or setting persisted. For alerts, a transmitted request is not delivery. For deletion, provider acceptance is not closure. For archive, uploaded parts are not a published/retrievable root.

## 8. Obligations turn long-running work into queryable state

An obligation has stable identity, owner region, anchor, deadline, progress predicate, effect relation, and terminal proof. Agents can resume and inspect without keeping one request open.

Examples:

- wait for stream continuity verification;
- await likely next-camera observation;
- reconcile notification delivery;
- complete archive publication/retrievability;
- run calibration and held-out validation;
- apply a deletion plan across replicas;
- build and activate a search/model generation.

Cancellation requests stop further optional work, drain children, and leave each obligation terminal or indeterminate. It does not erase history.

## 9. Hierarchical witnesses and value-of-information refinement

Prepared plans begin with sound coarse witnesses and refine only when conflict avoidance is valuable. A camera-control plan may first conflict at sensor level, then refine to PTZ range/time interval; an export may refine from event root to disjoint rendition children. Budget exhaustion means conservative conflict, not unsafe commit.

The same value-of-information logic applies to cognition: acquire the next camera/model/frame only when expected decision improvement exceeds cost, while hard freshness/safety floors remain fixed.

## 10. Deterministic commit combining and semantic merge ladder

FSS imports the short deterministic sequencing point and merge order:

1. replay intent against current state;
2. structurally merge disjoint stable-key domains;
3. compose only registered commutative operations;
4. reconcile/compensate external effects and replan;
5. reject ambiguity.

Raw byte merge and last-writer-wins are forbidden for event, policy, effect, calibration, and identity state.

## 11. Branch-per-agent planning

Each agent receives a cheap branch from a pinned anchor. It may propose associations, explanations, camera placements, model routes, or policy changes. Branch analysis can use graph/search/geometry. Merge produces an intent and conflict/evidence report; branch state never becomes observed reality.

This supports parallel agents without race-prone shared scratch state.

## 12. Capability filtering before query expansion

An agent’s authorized projection is built before search/graph expansion. It cannot infer hidden cameras, residents, zones, events, or counts through degree, paths, absence, snippets, or result totals. Capabilities are typed, time-bounded, and privacy-scoped.

No generic shell, SQL, Lua, vendor method, URL fetch, or arbitrary model prompt becomes an agent tool.

## 13. Progressive cognition under token budgets

Agents receive the smallest sufficient view:

1. exact typed state and high-attention deltas;
2. lexical/event candidates;
3. graph/temporal expansion;
4. semantic refinement;
5. evidence/citation shaping;
6. continuation handles and suggested next queries.

Every response includes anchor, freshness, completeness/claim class, degraded systems, and cost. Routine monitoring should consume hundreds of tokens, not raw frame dumps.

## 14. Checkpoint custody and restore epochs

Before consequential system mutations or migrations, FSS may create a checkpoint of ledger/object/configuration roots. Restore creates a new observation epoch, invalidates stale prepared plans/leases, and requires derived projections to rebuild or prove compatibility. A restored process cannot publish old staged work over the new epoch.

## 15. Knowledge remains exact-span and tainted

Device docs, runbooks, policies, and agent journals are indexed with exact source spans. Text may inform planning but cannot grant capabilities. Prompt-like camera/OCR/transcript content remains tainted through retrieval and summary.

## 16. Local qualification is architectural

DFMCP’s release doctrine directly matches the user’s instruction. The authoritative qualification executes locally through DSR from a clean source snapshot and exact sibling closure. GitHub workflow YAML is a portable job specification, not the trust root. Partial platform artifacts may be retained but never blessed by a release root.

## 17. FSS semantic owners

| Imported mechanism | FSS owner |
|---|---|
| Three planes and anchor model | `fss-types`, `fss-ledger` |
| Semantic intents/plans/witnesses | `fss-plan`, `fss-transaction` |
| Effects and obligations | `fss-effect`, `fss-obligation` |
| Agent branches | `fss-branch` |
| Progressive query/attention | `fss-retrieval`, `fss-agent` |
| Capability projections | `fss-policy` |
| Local qualification | `scripts/qualify.sh`, DSR contract |

## 18. Superficial imitations that would fail

1. One MCP tool per low-level camera/vendor command.
2. Screenshot-only state or raw JSON dumps.
3. Mutable global “current property” cache.
4. Treating adapter/provider acceptance as completion.
5. Retrying ambiguous effects without lookup/reconciliation.
6. Branching by copying and later writing branch rows into authority.
7. Filtering unauthorized graph results after traversal.
8. Allowing text/model output to grant authority.
9. Calling GitHub-hosted CI the release authority.
10. Adding every Franken dependency before its semantic owner and gate exist.

## 19. Admission evidence for `INT-DFMCP-001`

1. Anchor/delta/resume behavior under concurrent ingestion and projection lag.
2. Positive and negative read-witness fixtures over physical coverage domains.
3. Intent compile/replay/revalidate and deterministic plan fingerprints.
4. Effect lost-ACK, duplicate request, stale fence, observation, and reconciliation matrix.
5. Obligation persistence/resume/cancel/drain behavior.
6. Branch isolation and live-intent recompilation.
7. Capability noninterference before graph/search expansion.
8. Token-budgeted progressive response quality and continuation.
9. Checkpoint/restore epoch invalidates stale work.
10. Local DSR qualification proves clean source/sibling closure and never blesses partial targets.

## 20. Resulting architectural leap

FSS becomes an agent-operable semantic world model rather than a collection of streams and commands. Agents reason over coherent evidence, propose witnessed plans, and can later prove what happened—even when the physical or provider boundary behaved ambiguously.
