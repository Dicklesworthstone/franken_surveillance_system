# Request-bounded deletion authority for retained beliefs

`BoundedCommittedDeletionBeliefAuthority` makes deletion-history admission explicit before a
selected source closure can reach the derivation engine. The existing deletion-aware convenience
wrapper now uses the request's cancellation owner and default deletion admission limits. The
ordinary durable verifier still refuses deletion history without an explicitly selected owner.

The owner uses the same canonical deletion transition proof as `DeletionIndex`. A committed
header denies every deletable object immediately, including when all original bytes and publication
records still exist. Neither completion nor unlinking is a prerequisite for refusal. The proof
reader adds cancellation and plan-admission hooks without changing transition identities, ordering,
exact completion checks, or the legacy default reader. No partial denial map is returned.

## Admission and accounting

`DeletionBeliefLimits` bounds all history batches and entries, metadata read attempts, per-record
payload bytes, aggregate payload bytes, retained top-level plan rows, and distinct denied objects.
Native `StagingSpool::read_bounded` enforces the payload ceiling before allocation. The per-record
allowance can never exceed the existing deletion-format bound. Plan-row admission precedes the
allocation and sorting of expected tombstone/retraction transitions. The owner does not construct
unused import/unit indexes or parse a plan twice.

A successful metadata read is charged its exact payload length. A failed read keeps its entire
reserved payload allowance because its actual work is not known. This is logical admission, not a
measurement of filesystem syscalls, envelope bytes, hashing CPU, decoder scratch, or allocator
usage. One bounded canonical decode remains synchronous and format-bounded; cancellation does not
claim to preempt an individual decode or native read.

Each owner permits one attempt. `usage()` survives success, cancellation, or failure; attempting
to reuse the owner cannot reset it. Callers needing explicit limits or failure accounting construct
this owner and pass it to `verify_durable_belief_with_deletion_authority`. The compatibility unit
owner and convenience wrapper create a fresh default admission per call, not an aggregate budget
across unrelated requests. The outer durable replay, native custody capture, and derivation engine
retain their separate budgets and proof requirements.

## Regression scope

The focused runner now executes deletion belief tests explicitly; they were previously omitted.
New contracts exercise exact boundaries, every cancellation checkpoint, failed-read reservations,
unknown deletion families, and a real multipart deletion interrupted after its header. They test
both a live deployment and cold reopen: still-present affected evidence must be refused before the
engine runs, while an unrelated slot can still be independently rederived without mutation.

The quiet-frame activity fixture now publishes the unique set of source objects while preserving
all named evidence roles. This corrects the observed `NonCanonicalOrdering` setup failure without
relaxing manifest canonical ordering or interpreting no activity as absence.

Native execution results are reported by the pinned repository-owned runner, not by source presence.
This increment does not activate a model, authenticate a principal, supply missing privacy policy,
change deletion approval, finish an interrupted deletion, or confer effect/release authority.
