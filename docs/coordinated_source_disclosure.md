# One durable owner for coordinated investigation and source evidence

`DurableDisclosureStore` now composes existing work claims, investigation cases, source-registration
commitments, disclosure charges and continuation replay protection in the same session journal.
It does not create another writer, coordination protocol, artifact format or public operation ID.

## Open and operate on coordinated history

Use `open_existing_with_coordination` with an independently trusted journal root, session limits,
claim ceilings and a reconstructed catalog. The runtime still holds the exclusive protected path
ownership required by the existing journal. Stored claim limits cannot authorize larger allocations.
A source can remain absent on restart, but its committed custody requirement remains binding.

The owner exposes `enable_coordination`, `coordinate`, `enable_investigations` and `investigate`
through the existing native state machines. Refusal-side clocks, case revision preconditions, claim
leases, privacy checks and immutable history are unchanged. These methods neither expose mutable
session/catalog internals nor reset cursor state. Case history still uses the native immutable stored
limits and hard ceilings; this increment does not introduce a new independent case-ceiling profile.

`recover_existing_with_coordination` shares the ordinary recovery admission path: bounded read,
trusted-root check, complete semantic replay with independent claim ceilings, explicit tail policy,
and catalog compatibility all precede a recovery write. The legacy no-ceiling APIs continue rejecting
coordinated history. An uncertain claim or case append fences disclosure; an uncertain disclosure
append fences claims and cases. The same `reconcile_pending` resolves the actual append without
redelivering source, replaying a case command, replenishing tokens or forgetting continuations.

## Source-backed citations on that owner

`DurableDisclosureStore::cite_investigation_source` uses the existing native two-stage source
citation transaction. Its `SourceCitationTarget`, `SourceAcquisition`, `SourceCitationReceipt` and
`SourceCitationError` are publicly reexported from the investigations owner; no new receipt exists.

Before acquisition, it requires the exact source binding to appear in this journal's latest protected
catalog checkpoint. A live binding or imported catalog checkpoint alone is not sufficient. Establish
the requirement explicitly with `bind_source_object_durable`, or use a binding previously committed
by a successful disclosure. The new method authenticates the session/alias through staged session
admission, checks persisted custody metadata, then delegates case/privacy/anchor/deadline/CAS and
live original-source verification to the existing owners. Durable metadata never substitutes for
a fresh source read.

Only direct exact H3 requests without downgrade or a continuation are accepted. The temporary
catalog used by the case-facing hydrator is discarded, so unpublished cursor changes cannot escape
into the disclosure catalog. Existing issued/consumed continuations stay owned by the ordinary joint
disclosure path. Source bytes are neither returned to the case caller nor written to the journal.

Acquisition and citation are still TWO commits. Once acquisition is charged, a failed or uncertain
link cannot erase that charge. `SourceCitationError::Link` preserves the acquisition witness; inspect
and reconcile rather than blindly retry. Source-citation receipts are not ordinary disclosure
admissions. A citation records which authorized original was acquired, not a physical-world finding,
current applicability, calibrated confidence or effect permission. Existing case rebase/readmission
and hypothesis-assessment rules remain unchanged.

## Reproduce the native contracts

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --lib agent_session::checkpoint::journal::disclosure::recovery::coordinated
```

The existing `scripts/test_belief_provenance.sh` disclosure target already includes this module.
Six mixed-history tests cover claim/case/source-continuation interleaving across restart, independent
ceilings, both directions of append fencing, all claim append fault phases, rejected recovery with
unchanged torn bytes, and lost acknowledgements. Six additional citation tests cover acquisition and
counterevidence replay, volatile/imported checkpoint refusal, exact case/session admission, charged
but unlinked capacity failure, ambiguous acquisition appends, and preservation of an unrelated live
continuation through case acquisition and restart. The checkpoint lookup contract also checks exact,
conflicting and absent requirements.

The implementation is a reference-library integration, not wholesale CLI migration or an
application authentication/privacy service. It changes no qualification gate or durable encoding.
The editing environment has no Rust toolchain; authored tests require native compilation/execution
before they count as validation. Hosted focused tests remain supplementary to repository qualification.
