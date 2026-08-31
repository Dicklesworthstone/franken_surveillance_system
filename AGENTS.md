# AGENTS.md

Read this entire file and `COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md` before editing.
The repository is designed for autonomous coding agents, but it does not permit an agent to infer
missing authority, lower a gate, or replace a specified architecture with a quick substitute.

## Prime directive

Build a deterministic, evidence-native semantic control plane for owner-authorized physical
sensors. Preserve uncertainty and provenance. Keep cognition derived. Make effects explicit,
idempotent, capability-scoped, and later verifiable.

## Truth hierarchy

1. Machine-readable registries and versioned schemas.
2. Normative comprehensive plan and ADRs.
3. Tests and retained proof bundles.
4. Implementation.
5. Explanatory documentation.

When these disagree, do not choose the most convenient one. Record the drift, identify the owning
contract, and repair the set coherently.

## Non-negotiable architecture

- Rust 2024 on the pinned nightly toolchain.
- Asupersync only for asynchronous orchestration; no Tokio adapters hidden behind features.
- `#![forbid(unsafe_code)]` in every FSS workspace crate, target, example, test, and build helper; there is no local exception path.
- Production media, model, graph, storage, and protocol semantics are first-party pure Rust. Foreign frameworks/applications are laboratory or migration oracles only.
- `Cx` or an equivalent explicit authority reaches every I/O, time, sleep, lock, network,
  secret, effect, and sealed laboratory-oracle process boundary.
- Region ownership; cancellation is request→drain→finalize; no orphan work.
- Authority, cognition, and effect planes are type-distinct.
- Canonical history is one ordered `EvidenceDeltaBatch` universe. Derived state is anchor-pinned and rebuildable.
- Negative reads require `CoverageWitness`; semantic plans require read/write witnesses.
- ATP moves immutable object graphs only and never carries effect authority.
- Root-last publication distinguishes staged, visible, durable, replicated, protected, and retrievable states.
- Graph algorithms use registered projections, CGSE tie-breaks, and complexity/output witnesses.
- Immutable model/device/config generations.
- Stable IDs are never renumbered; superseded entries remain tombstoned.

## Workflow

1. Orient: inspect status, registries, the relevant plan section, and recent negative evidence.
2. Establish scope: stable requirement IDs, files, authority changes, migrations, and gates.
3. Implement the smallest coherent vertical contract—not a fake end-to-end demo.
4. Add deterministic reference behavior before optimized or proprietary behavior.
5. Add failures first: cancellation, packet gaps, clock skew, corrupt data, stale firmware, model
   crash, partial archive publication, duplicate requests, and indeterminate outcomes.
6. Run the direct local qualifier, deterministic reference/differential/fault lanes, and every affected claim-specific lane. Workflow YAML contains no unique logic.
7. Update implementation status and evidence pointers without upgrading claims beyond the proof.

## Prohibited shortcuts

- Calling adapter acceptance “streaming.”
- Calling a decoded frame “retained evidence” without source custody or an explicit omission.
- Calling one camera’s model score “corroborated.”
- Treating a missing detection during a coverage gap as evidence of absence.
- Letting a VLM trigger an effect directly.
- Mixing embeddings or scores across model generations.
- Downloading “latest” model weights at runtime.
- Storing secrets in config, logs, traces, evidence, prompts, or fixtures.
- Reusing a vendor’s cloud token outside its exact adapter capability.
- Presenting a mobile screen capture or app automation path as a stable native integration.
- Adding a global lock, mutable singleton, unbounded channel, detached thread, or unbounded retry.
- Silently changing retention, redaction, identity, or alert policy from learned feedback.
- Optimizing before the operation-cost row and semantic oracle exist.
- Adding a foreign production runtime behind IPC and calling the system pure Rust.
- Treating a green hosted workflow as release authority or publishing a partial target matrix.

## Agent-facing output

Machine output is versioned JSON with stable exit codes. Human output may be rich, but it must not
be the only contract. Explain every event using evidence identities, model/policy generations,
uncertainty, sensor health, and counterfactuals. Bounded queries return continuation anchors rather
than dumping the world.

## Security boundary

Interoperability work is limited to devices and accounts the operator owns or is explicitly
authorized to test. Never implement credential theft, authentication bypass, third-party account
access, broad scanning, persistence on vendor devices, or evasion. Reverse engineering must be
minimal, documented, reproducible against lab fixtures, and isolated from production credentials.

## Local release authority

`scripts/qualify.sh` is the semantic qualification entrypoint. DSR executes it from clean snapshots on controlled native hosts with exact sibling closure. GitHub workflows are portable supplementary specifications only. No agent may weaken a lane because hosted capacity is unavailable.

## Definition of done

A requirement is done only when its contract, success/failure semantics, migrations, deterministic
reference, fault tests, compatibility identity, privacy/security behavior, performance cost, proof
bundle, status, and documentation agree. “Code exists” is not a completion state.
