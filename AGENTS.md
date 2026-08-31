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
- `#![forbid(unsafe_code)]` in ordinary workspace crates.
- Codec, model, and proprietary vendor runtimes are supervised processes outside the trust root.
- `Cx` or an equivalent explicit authority reaches every I/O, time, sleep, lock, subprocess,
  network, secret, and effect boundary.
- Region ownership; cancellation is request→drain→finalize; no orphan work.
- Authority, cognition, and effect planes are type-distinct.
- Canonical evidence is immutable. Derived state is rebuildable.
- Root-last publication for object graphs.
- Immutable model/device/config generations.
- Stable IDs are never renumbered; superseded entries remain tombstoned.

## Workflow

1. Orient: inspect status, registries, the relevant plan section, and recent negative evidence.
2. Establish scope: stable requirement IDs, files, authority changes, migrations, and gates.
3. Implement the smallest coherent vertical contract—not a fake end-to-end demo.
4. Add deterministic reference behavior before optimized or proprietary behavior.
5. Add failures first: cancellation, packet gaps, clock skew, corrupt data, stale firmware, model
   crash, partial archive publication, duplicate requests, and indeterminate outcomes.
6. Run policy, formatting, check, Clippy, unit, integration, replay, and affected qualification
   lanes.
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

## Definition of done

A requirement is done only when its contract, success/failure semantics, migrations, deterministic
reference, fault tests, compatibility identity, privacy/security behavior, performance cost, proof
bundle, status, and documentation agree. “Code exists” is not a completion state.
