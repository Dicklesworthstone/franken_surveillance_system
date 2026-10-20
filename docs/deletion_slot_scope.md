# Committed deletion also revokes publication scope

A deletion plan has two different read restrictions: deleted object digests and retracted
publication slots. They are not interchangeable. A root can remain physically retained, including
under another authorized slot, while the selected slot is revoked. A committed header establishes
both restrictions before individual retraction deltas or filesystem unlinking finish.

The durable belief verifier now calls `DurableBeliefDeletionAuthority::verified_denials_for_slots`
with its exact independent slot selection. The bounded reference owner validates the canonical
history once, checks selected names against each plan's retractions, then returns object denials.
It does not mark every alias of the same root deleted. Selection is bounded and canonical before
metadata I/O; cancellation and the existing single-attempt allowance apply throughout.

The old object-only method remains usable by object-only consumers. Its result cannot serve as
slot authorization. The new trait method defaults to refusal, so an older custom owner must
explicitly implement slot validation before it can admit deletion-bearing durable beliefs. The
compatibility reference owner delegates to the bounded implementation; no alternate proof or
unmetered retry is introduced.

The native admission contracts now require `Selection` before capture for a header-retracted
slot, retain the live/cold-reopen cases, and add single-attempt scope admission, duplicate selection
and legacy object-only refusal cases. The existing focused runner includes that test target.
Native execution is a separate validation step; this document does not claim a passing run,
production privacy authorization, completed deletion, effect authority or release qualification.
