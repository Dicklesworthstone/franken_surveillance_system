# Semantic handles and progressive hydration

**Status:** deterministic reference implementation present; production surface parity and retained release qualification remain in progress  
**Primary requirement:** FSS-210  
**Semantic protocol:** `fss/1`

## Purpose

Agent-facing views must be compact without forcing the agent to choose between an opaque summary and unrestricted source access. FSS therefore represents expandable evidence with an immutable `SemanticHandle` and a bounded H0–H4 hydration ladder.

A semantic handle is not a mutable URL and is not an alias for “whatever is current.” It names one exact subject identity and subject digest. Availability, retention, privacy policy, cost, and capability requirements live in a versioned descriptor whose digest changes whenever those delivery conditions change. A descriptor revision may therefore report that the exact subject is superseded, deleted, expired, corrupt, privacy-transformed, or not observable without rebinding the stable handle to different bytes.

## The H0–H4 ladder

| Level | Meaning | Typical material |
|---|---|---|
| `H0` | Identity and delivery metadata | subject identity, digest, source, bounds, availability, authority anchor, estimated cost |
| `H1` | Typed semantic synopsis | propositions, provenance, contradictions, quality, omissions, compact measurements |
| `H2` | Redacted decision artifact | crop, keyframe, trajectory, graph neighborhood, compact derived bundle |
| `H3` | Authorized source evidence | exact packets, retained object bytes, full-resolution evidence within the granted scope |
| `H4` | Qualification or explicitly granted debugging material | differential traces, internal fixtures, retained diagnostic expansion |

Published levels must be contiguous from H0. A descriptor cannot advertise H0 and H2 while silently omitting H1. Every advertised level has an exact capability set and a complete multidimensional `BudgetVector`, including latency, tokens, bytes, model calls, CPU, accelerator, energy, network, storage operations, privacy exposure, and operator attention.

H4 is separately clamped. It may be absent, qualification-only, or available to qualification plus an explicit debugging capability. Routine mission reasoning cannot obtain H4 merely because a broad evidence-read capability exists.

## Immutable identity and versioned descriptors

`SemanticHandle.handle_id` is derived from the immutable subject coordinates:

- canonical subject identity;
- exact subject digest;
- registered semantic type;
- stable source identity;
- optional capture interval;
- optional spatial or graph scope;
- transform already applied to this exact subject.

The descriptor additionally binds:

- exact `ContractBasis` and authority anchor;
- privacy class;
- current availability;
- retention deadline;
- published hydration levels;
- per-level capabilities and costs;
- H4 laboratory policy;
- derivative-handle identities;
- deterministic publication time.

Changing descriptor policy changes `descriptor_digest`, not `handle_id`. Changing the subject bytes or semantic identity changes the handle itself. A privacy-transformed derivative therefore receives its own subject digest and stable handle; it never overwrites the original binding.

## Exact requests

A `HydrationRequest` binds all of the following:

- stable handle identity;
- expected descriptor digest;
- expected immutable subject digest;
- exact authority anchor;
- requested level;
- whether an explicit lower-level result is acceptable;
- delegated capabilities;
- authorized privacy classes;
- full resource ceiling;
- declared purpose;
- exact continuation cursor, when progressively hydrating;
- deterministic issue time.

A progressive cursor is scoped to evidence hydration and bound to the handle, session, registered hydration view, contract basis, authority anchor, ladder-policy digest, and next level. Reusing a cursor against another handle, session, descriptor lineage, anchor, or position fails as a typed continuation error rather than restarting from hidden conversational state.

## Reference selection behavior

The reference catalog stores exact descriptor revisions and exact artifacts by handle, descriptor, and level. Hydration performs the following checks in order:

1. verify request, descriptor, and immutable subject identity;
2. resolve the exact descriptor revision rather than silently selecting the latest revision;
3. return a typed unavailable receipt for deletion, expiry, corruption, privacy transformation, supersession, or non-observability;
4. enforce privacy class and per-level capability requirements;
5. enforce the H4 purpose/grant clamp;
6. enforce the full resource vector;
7. select the requested level, or the richest permitted lower level only when downgrade was explicitly allowed;
8. verify the exact artifact payload and proof roots;
9. publish a receipt and, when appropriate, an exact cursor for the next contiguous level.

An explicit downgrade records both requested and delivered levels and returns partial response completeness. It is never presented as complete satisfaction of the richer request. When downgrade is not allowed, the operation returns a stable typed failure such as capability denied, privacy denied, laboratory grant required, level unavailable, or budget exceeded.

## Proof-bearing responses

A successful `HydrationResponse` contains an artifact and a `HydrationReceipt`. Cross-validation proves agreement among:

- request digest;
- handle and descriptor identities;
- immutable subject digest;
- authority anchor;
- requested and delivered levels;
- exact charged cost;
- payload and artifact digests;
- retained proof roots;
- response completeness;
- invalidators;
- continuation scope and position.

An unavailable exact subject returns no artifact, no continuation, and zero execution cost. The receipt preserves the distinct state and maps it to an explicit completeness value. Deletion and expiry therefore cannot be confused with an empty artifact or a successful negative read.

## Determinism and replay

Equivalent handles, requests, artifacts, and receipts use canonical encoding and produce identical digests. Registration is idempotent only for identical content. Reusing a stable handle identity for a different immutable subject is a `semantic_handle_rebound` failure.

The reference tests cover:

- immutable handle identity across descriptor revisions;
- contiguous ladder enforcement;
- exact cursor binding;
- payload and receipt tamper detection;
- capability and privacy denial;
- full-vector budget rejection and explicit downgrade;
- typed deleted and expired outcomes;
- H4 qualification/debugging clamps;
- deterministic replay and descriptor mismatch.

## Current boundary

This implementation establishes the dependency-free core contract and deterministic reference behavior. FSS-210 remains broader than code presence. Completion still requires:

- JSON Schema and machine-registry agreement;
- first-class binding of every context-pack expansion to a published descriptor;
- equivalent CLI, MCP, TUI, report, and handoff payloads;
- persistent object/retention integration and deletion proofs;
- stale/crash/cancellation and multi-agent schedules;
- retained QL-AGENT qualification roots and GATE-115 evidence.

Until those surfaces and proofs exist, documentation and status must describe this as a qualified reference slice rather than a production-complete feature.
