# Deletion-aware deployment source disclosure

`fss_reference::deletion::belief::hydration` connects H3 source hydration to current durable
ledger authority, committed deletion plans and exact local publication slots. A publisher-only
reader cannot see a deletion header that is durable before root retractions and unlinking finish.
Still-present bytes and a local publication record are therefore insufficient read authority.

## Consumer path

The authority owner selects the exact current anchor, a slot whose entire closure may be verified,
explicit read-only I/O, native/deletion resource limits and cancellation. Construct a fresh
`DeletionAwareSourceReader` for each binding or disclosure, then use
`ReferenceHydrationCatalog::bind_deployment_source_object` or
`ReferenceHydrationCatalog::hydrate_from_deployment_source` respectively.

The ordinary hydration pipeline still admits the exact descriptor, trusted privacy/capability
grants, retention, full-vector artifact quote and continuation before invoking the reader. No
second request or receipt protocol is introduced. Successful H3 responses retain the existing
`SourceObjectBinding::validate_response` consumer check. The catalog stores binding metadata,
never a source-payload cache. A raw source cannot stand in for a privacy mask or redaction.

The reader verifies the opened journal identity/head, validates canonical deletion authority and
selected slot revocation, checks the current authority-plane reachability revision, then captures
the complete selected native closure. An unused corrupt or deleted sibling also refuses. Capture
rehashes every object and brackets the operation with matching publication catalogues. Exact slot,
root, child count and native record digest must agree; another slot with equal bytes is not a
substitute. The journal identity/head is checked again before returning the subject bytes.

A committed deletion header immediately denies its whole planned closure and selected retracted
slots. This does not wait for completion, individual retraction deltas or filesystem unlinking.
Unrelated intact authorized slots remain usable. Disclosure never resumes or repairs deletion.

## Bounds and remaining boundaries

One reader permits one custody attempt, including an initially cancelled attempt. Deletion usage
survives refusals. Completed native capture reports read bytes, filesystem calls and retained
payload bytes separately from the artifact quote; a failed capture has no unified partial-I/O
receipt yet. Journal-head checks and metadata reads use the opened owners' explicit capabilities;
source closure capture uses the supplied read-only I/O capability. These remain separate budgets.

Cancellation and stale authority return no source. A custody failure does not silently downgrade
into a preview, consume a continuation, or become evidence of absence. Explicit lower-level,
expired or otherwise unavailable deliveries retain the ordinary hydration semantics and do not
invoke the source reader. Existing cached non-source artifacts do not gain a new deletion proof.

This is a reference-library consumer integration, not a CLI authentication service or wholesale
migration of every caller. Trusted grants and current privacy projection still belong to their
owner. The lower-level generic and standalone publisher APIs remain available for their declared
scopes; deployment callers should use the new path. Capture is an observed consistency boundary,
not an atomic filesystem snapshot, future retention lease, physical-truth certificate or effect
permission.

## Native contracts

The focused runner includes ten new deployment tests and the existing local source suite. They
cover cold reopen with unchanged receipts, no payload caching or writes, capability/privacy/quote
and expiry gates before I/O, cancellation without refill, stale anchors, exact closure byte bounds,
corrupt unused siblings without silent downgrade, missing selected records with surviving aliases,
unledgered publication, and live/cold multipart deletion headers with still-present original media.

Run `bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance` on the pinned native
`nightly-2026-08-31` toolchain. Source presence is not passing-test evidence. The existing repository
qualification gate remains intact; focused tests and hosted execution are not release authority.
