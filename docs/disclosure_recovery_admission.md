# Reject incompatible disclosure recovery before changing the journal

`DurableDisclosureStore::recover_existing` admits the reconstructed source and cursor catalog
before asking its existing native journal owner to synchronize or truncate anything. Previously,
the session owner could discard an incomplete suffix successfully and only then discover that the
caller's rebuilt catalog violated a committed custody requirement. That refusal lost the suffix
without returning a usable disclosure owner or its recovery receipt.

The order is now: bounded read, independently supplied root check, complete semantic replay,
explicit incomplete-tail policy, catalog compatibility, then native recovery. The catalog admission
uses the same helper as live synchronization and recognizes both source-registration and charged
disclosure snapshots. Rejected source bindings, cached H3 replacements, metadata-capacity limits,
and incompatible or unjournaled cursors leave the file, including its unfinished suffix, unchanged.
No source reader is called during recovery. The read-only preflight history is released before
native recovery rereads the journal.

A missing descriptor or source remains admissible. Its recorded custody requirement survives,
constraining any later reconstruction; absence is not permission to substitute another publication
or reader. Valid recovery preserves charges and consumed cursor records. It does not refund tokens,
redeliver a response, recreate source bytes, or treat a diagnostic inspection as root authorization.

The existing session recovery owner is unchanged: it rechecks the full observed report on the same
file descriptor it will trim, removes only an explicitly authorized incomplete suffix, synchronizes,
and verifies the resulting prefix before installing a writer. Post-recovery live synchronization
also remains. This is not transactional filesystem rollback: native I/O failure or external mutation
after preflight may still require explicit inspection. The namespace must remain exclusively owned
and protected, and the committed root must be independently trusted. Coordination journals still
require their own independently supplied ceilings; this API does not add that profile.

No durable encoding, public API signature, tail policy, source grant or qualification gate changes.
The additional read and replay are bounded by the existing session journal byte and record ceilings;
these are not measured CPU or physical I/O costs. Complete semantic corruption still refuses rather
than becoming a repair opportunity.

## Regression contracts

Nine tests under the existing disclosure library target use exclusive synthetic journals and real
BodySync/CommitSync fault injection. They cover incompatible custody followed by valid recovery,
cached source substitution, metadata ceilings, unjournaled cursors, absent-source recovery, retained
charges and consumed cursors, explicit Reject and wrong-root refusals, corrupt complete semantic
history, and a fully committed registration whose acknowledgement was lost. Assertions compare the
entire file before and after refusal and the exact discarded-tail digest/length on accepted recovery.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --lib agent_session::checkpoint::journal::disclosure
```

The existing `scripts/test_belief_provenance.sh` already selects this module. These tests are authored
but have not been compiled or executed in the editing environment, which has no Rust toolchain.
The last observed hosted run for the preceding registration increment stopped at dependency-policy
validation before native execution. Neither source review nor queued checks are release qualification.
