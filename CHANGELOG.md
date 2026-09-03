# Changelog

All notable changes to Franken Surveillance System are recorded here. The project is pre-release; entries describe implemented and retained repository state, not production qualification unless explicitly stated.

## Unreleased

### Added

- Added dependency-free semantic-hydration contracts to `fss-core`:
  - immutable `SemanticHandle` identity over exact subject coordinates;
  - independently versioned descriptor digests for availability, retention, privacy, capability, and cost policy;
  - contiguous H0–H4 hydration ladders;
  - exact `HydrationRequest`, `HydrationArtifact`, `HydrationReceipt`, and `HydrationResponse` objects;
  - typed availability for superseded, deleted, expired, corrupt, privacy-transformed, and not-observable subjects;
  - stable hydration failures with deterministic recovery classes;
  - exact evidence-hydration continuation cursors bound to handle, session, basis, anchor, ladder policy, and next level.
- Added a deterministic reference hydration catalog with exact descriptor lookup, idempotent registration, immutable-subject protection, capability/privacy enforcement, full-vector budget checks, explicit downgrade, H4 purpose gating, typed unavailable receipts, proof-root closure, and deterministic continuation issuance.
- Added module-private, adversarial, and external-consumer tests for handle revisioning, ladder gaps, cursor misuse, subject substitution, descriptor mismatch, payload tampering, capability/privacy denial, budget downgrade, deleted/expired outcomes, H4 access, and deterministic replay.
- Added `docs/SEMANTIC_HYDRATION.md` as the normative reference guide for FSS-210’s implemented slice and remaining qualification boundary.
- Added proof-bearing reference situation publications composed from a `SituationCapsule`, categorized control envelope, complete resource state, semantic context pack, compression receipt, and deterministic publication digest.
- Added deterministic `MeaningfulDelta` classification with protected non-coalescible contradiction, coverage-loss, plan-invalidation, obligation, effect-uncertainty, authority, and terminal transitions.
- Added silence certificates for comparisons that prove no decision-relevant change.
- Added exact continuation streams with content-bound entries, page digests, monotone positions, expiry, stream identity, and wrong-stream rejection.
- Added guarded agent projections that require the exact local operation receipt before exposing alert commit. Missing, committed, acknowledged, failed, cancelled, or indeterminate state exposes status/reconciliation rather than blind dispatch.
- Added root-closed reference handoffs and deterministic decision fingerprints for replay comparison.
- Added the complete multidimensional `BudgetVector`, including accelerator time and energy, to canonical action, projection, compression, and continuation digests.

### Changed

- Agent-facing projection now preserves resource pressure as its own semantic dimension instead of laundering it into material world change.
- Meaningful-delta comparison now separates semantic world content from routine successor-anchor movement, permitting certified silence across harmless authority commits.
- Contradiction resolution and removal of a previously known premise are retained as critical decision-impact changes.
- Compression receipts permit explicitly receipted partial semantic classes while continuing to forbid omission of critical items, contradictions, or invalidations.
- Public situation compilation routes through the effect-state guard by default.
- Expansion and continuation semantics are progressively moving from conversational strings toward content-bound, capability-scoped contracts.
- Hosted GitHub execution remains supplementary. Repository-owned local qualification and retained DSR receipts remain the release authority.

### Fixed

- Prevented a prepared alert plan from being treated as proof that an operation has not already crossed an external boundary.
- Prevented forged or structurally inconsistent local effect receipts from preserving commit authority.
- Prevented unavailable affordances from appearing in the actionable `NEXT` frontier.
- Prevented duplicate or overlapping knowledge evidence, duplicate claims, duplicate obligations, malformed possible-world cores, and predicted claims from becoming irreversible-effect premises.
- Fixed semantic comparison across successor anchors so stable possible worlds do not appear changed solely because their authority anchor advanced.
- Fixed silence-certificate validation so the certificate witness must equal the enclosing delta witness.
- Removed a temporary source-snapshot workflow that violated the repository’s workflow-delegation policy.
- Removed policy-sensitive wording from Rust documentation without changing runtime semantics.

### Qualification state

The deterministic Rust reference implementation is substantially broader than the initial skeleton, but no public production-completeness claim is made. Outstanding work includes JSON Schema and registry agreement for the new contracts, persistent object/retention integration, CLI/MCP/TUI/report equivalence, multi-agent claim and lease semantics, remaining `TEST-AGENT-*` families, QL-AGENT aggregate thresholds, GATE-115, native device/model/graph/storage implementations, and a complete locally qualified release root.

## 0.1.0 - Foundation snapshot

### Added

- Pure-Rust workspace and crate topology for the semantic reference kernel, object store, durable evidence ledger, publication spine, reference acquisition/replay path, and CLI laboratory.
- Canonical identities, hashing, timestamps, evidence anchors, sensor capsules, coverage witnesses, event hypotheses, effect journals, obligations, receipts, and root-last object publication.
- Deterministic virtual camera source generation, delivery mutation, mock-model execution, unknown-presence policy evaluation, alert preparation/dispatch/reconciliation, and replay bundles.
- Repository constitutions, ADRs, machine registries, JSON Schemas, local qualification scripts, dependency audits, release tooling, and layered integrity manifests.
- Agent cognition and control architecture covering missions, sessions, epistemic states, situation frames, possible worlds, affordances, plans, effects, learning, workspaces, and handoffs.

### Security and correctness

- Workspace crates forbid memory-unsafe Rust.
- Negative claims require explicit coverage evidence.
- Model output alone cannot grant effect authority.
- External effects use prepare/commit/watch/reconcile semantics and retain indeterminate outcomes.
- Canonical publication is child-first and root-last.
- Stable identifiers are never silently renumbered or rebound.
