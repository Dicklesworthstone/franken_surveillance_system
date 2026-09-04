# Semantic Hydration Registry

This registry is the human-readable mirror of `architecture/semantic_hydration.json`. The machine registry is authoritative when prose and machine state differ.

## Purpose

A semantic handle is a stable reference to one immutable subject. It is not a mutable URL, a promise that media still exists, or authority to reveal the subject. Availability, retention, privacy class, capabilities, cost, and the current authority anchor live in a versioned descriptor. A descriptor revision may change those fields without changing the handle. It may never change the subject bound to the handle.

## Hydration ladder

| Level | Contract |
|---|---|
| `H0` | Identity, source, bounds, authority, availability, privacy class, level inventory, and priced expansion metadata. |
| `H1` | Typed semantic synopsis, provenance, contradictions, quality, completeness, and omissions. |
| `H2` | A privacy-transformed decision artifact such as a crop, keyframe, trajectory, or graph neighborhood. |
| `H3` | Authorized exact source evidence such as packets, immutable object bytes, or full-resolution media. |
| `H4` | Qualification material or explicitly granted debugging expansion. Routine mission reasoning cannot obtain H4. |

Published levels must form a contiguous prefix beginning at H0. Every level has an exact capability set and complete multidimensional cost. An artifact is bound to one descriptor digest and one level, and its proof roots must include the immutable subject digest.

## Context expansion binding

The `expansionHandles` strings in the v1 context-pack and compression-receipt schemas are stable **slot identities**. They are not trusted as self-authenticating handle URLs. This preserves interpretation of existing v1 bytes while closing the ambiguity through a separate proof-bearing contract.

Every emitted slot is bound by `ContextExpansionBindingSet` to exactly one `SemanticHandleReference`. The reference pins:

- immutable handle and subject identity;
- exact descriptor revision;
- exact `ContractBasis` digest;
- descriptor authority anchor;
- exact H-level;
- exact hydration-ladder policy digest.

The binding set must equal the union of item-level and receipt-level expansion slots. Missing, duplicate, and unexpected slots fail closed. A descriptor from another site lineage or ledger epoch, or from a commit newer than the context pack, is rejected. The bound reference publication carries only the exact descriptor revisions it uses; unused ambient descriptors are also rejected so a handoff cannot hide unreviewed authority state.

For receipt-level slots, the receipt's purpose and full multidimensional price must exactly match the descriptor-bound binding. CLI, MCP, TUI, report, and other renderers therefore cannot advertise a cheaper expansion or silently reword what the expansion reveals. Item-local slots may supply their bounded purpose in the binding because the v1 item schema carries no price or purpose field.

A bound handoff retains the publication, binding-set, individual binding, handle-reference, subject, descriptor, and ladder-policy digests. A resumed agent can consequently verify expansion meaning without consulting conversational history or accepting a mutable “latest descriptor.”

## Request evaluation

The reference implementation evaluates a request in this order:

1. Verify request and descriptor digests.
2. Require the descriptor to be the current revision for the stable handle.
3. Require exact subject, contract-basis, and authority-anchor agreement.
4. Resolve retention and explicit availability.
5. Require the requested level and exact artifact to be published.
6. Require the descriptor privacy class.
7. Require every level capability.
8. Apply the H4 qualification/debugging clamp.
9. Require the complete cost vector to fit the request budget.

A direct request with `allow_lower_level=true` may receive the richest lower level satisfying every clamp. The receipt is then `partial` relative to the original request. A request carrying a continuation may not fall back: the cursor denotes one exact next level.

## Exact continuations

Hydration cursors use scope `evidence_hydration`, view `AVIEW-HYDRATION`, the stable handle as the stream identity, the exact descriptor digest as the source, and the next H-level ordinal as the position. They bind the contract basis, session, basis/resume anchor, ladder-policy witness, high-water mark, prior cursor digest, issue time, and retention-horizon expiry.

A cursor from another handle, descriptor, session, view, authority anchor, level, or contract basis is rejected rather than guessed forward.

## Availability and non-results

Unavailable subjects return typed non-payload receipts. Supported states are `superseded`, `deleted`, `expired`, `corrupt`, `privacy_transformed`, and `not_observable`. These are not interchangeable:

- `expired` and `superseded` are stale relative to a previous descriptor.
- `deleted`, `corrupt`, and `not_observable` do not certify physical absence; they report that the exact artifact cannot be observed.
- `privacy_transformed` points to a distinct derivative handle when one exists. It never silently substitutes derivative bytes under the original identity.

Unavailable responses charge no hydration cost and carry no continuation. They still retain the exact request and descriptor roots and list the conditions that invalidate reuse.

## Proof and invalidation

A successful receipt retains the request digest, descriptor digest, immutable subject digest, artifact payload digest, artifact digest, full cost, completeness, authorization context, and exact next cursor when richer material remains. Reuse is invalidated by descriptor revision, authority-anchor change, retention, capability scope, or privacy scope.

A context publication that exposes expansion slots is not self-contained until its binding-set digest and exact descriptor revisions are retained with it. Bare slots cannot authorize hydration.

## Implementation status

The dependency-free contracts live in `fss-core::hydration` and `fss-core` context-binding modules. The deterministic in-memory hydration oracle lives in `fss-reference::ReferenceHydrationCatalog`; descriptor-bound context publications live in `fss-reference::BoundReferenceSituationPublication`. This is a reference vertical slice, not yet a production object-plane hydrator or a release claim. Production completion still requires object-store publication, privacy-policy integration, protocol surface parity, fault campaigns, and local DSR qualification.
