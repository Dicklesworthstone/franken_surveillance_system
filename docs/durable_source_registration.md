# Acknowledge source registration only after its custody requirement is durable

`DurableDisclosureStore::bind_source_object_durable` closes the interval between successfully
checking a source binding and the first later disclosure checkpoint. It can run before any session
exists. The caller supplies an exact descriptor, publication root, independently authorized reader
and trusted time. Success returns `JournaledSourceBinding` with the checked metadata and confirmed
journal root. No original bytes are returned or saved in the journal.

This is an authority-owned registration operation, not an agent request, read capability or
zero-token disclosure. The caller still authenticates policy and source access. A deployment source
uses the existing `DeletionAwareSourceReader`: journal identity, current anchor, committed deletion
state, exact publication slot, whole retained closure and resource/cancellation checks are unchanged.
Standalone source readers remain standalone; persistence does not promote their assurance level.

## One owner and one history

The existing protected session journal carries a private `fss.reference_source_registration.v1`
envelope under its existing checkpoint record kind. The envelope contains the exact prior session
checkpoint identity, unchanged session bytes, the existing v2 catalog checkpoint, selected descriptor
and custody-binding digests, and registration time. It adds no second journal or alternative evidence
history. Its requirements constrain local reconstruction; they do not claim present remote custody.

Replay reconstructs an exact transition: add or reaffirm ONE selected source requirement; preserve
all other source commitments and every cursor record byte-for-byte. Registration cannot create,
consume, resurrect or retire a cursor, even an expired one. It cannot change sessions, clocks within
sessions, grants, aliases, balances or closed-state tombstones. It is not included in disclosure
admission queries. The separate catalog clock cannot regress across registrations and disclosures.

Other bindings currently present in memory are not implicitly committed by this operation. Later
normal disclosures retain their existing whole-catalog checkpoint semantics. Initial catalog creation
and the older `bind_source_object` API remain volatile until an enclosing checkpoint commits; callers
requiring a durable registration acknowledgement should explicitly use the new operation.

## Refusal and uncertain append

Registration checks the current descriptor, retention and known journal capacity before source I/O.
The source owner checks its bounded live custody; any failure leaves no new binding or commitment.
The candidate binding and catalog checkpoint remain staged until the journal append synchronizes.
Exact output size and journal capacity are checked before append; a known-full record allowance is
refused before touching source. Reader-owned work ceilings and cancellation remain independent of
session token quotations. These operations do not claim measured CPU or full physical I/O costs.

An uncertain append fences the owner. Existing `reconcile_pending` or explicit cold recovery classifies
whether the record committed. A committed requirement survives even if its acknowledgement was lost;
a noncommitted attempt does not invent one. Recovery performs no source read, does not recreate the
staged binding or payload, and never refunds/recharges a session. A later explicit registration retry
revalidates custody and appends a new bounded record; it does not pretend a prior read is still current.

Cold reopen may omit unavailable descriptors and source bindings. The saved requirement remains and
rejects a weaker reader, another equal-content slot or a cached H3 replacement. Correct reconstruction
still requires the original custody profile and fresh checks. Missing source cannot widen authority.

## Compatibility

Existing disclosure and v1/v2 catalog formats remain unchanged. Older builds reject the new private
registration envelope rather than silently ignoring its requirements. This feature does not upgrade
old histories or reset replay state. The owner must protect the journal namespace, preserve its root
independently, and reconstruct trusted descriptors. It is not a new authentication service, cross-
process coordinator, effect interface, retention lease, deletion repair or release qualification.

## Native regression coverage

Four pure transition contracts check exact one-binding changes, unchanged active/consumed/expired
cursors, monotone time and byte limits. Six native-journal contracts cover initial registration,
malformed/truncated records, source refusal, capacity admission, live append reconciliation and cold
recovery after body/commit synchronization faults. Five deployment contracts add original-reader and
slot substitution, actual source closure corruption, cancellation, unrelated volatile bindings and
registration interleaved with charged disclosures and consumed continuations over repeated restart.

```sh
bash scripts/test_belief_provenance.sh /tmp/fss-belief-provenance
```

The runner includes the complete disclosure-journal tests, checkpoint tests, and
`source_binding_registration_contract`, alongside the existing provenance/deletion/custody targets.
The repository qualification lane is unchanged. These tests were authored but native compilation,
execution and rustfmt were not available in the editing container; no passing-test claim is made.
