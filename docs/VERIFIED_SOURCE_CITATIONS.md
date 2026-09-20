# Live source acquisition into an investigation (FSS-210 / FSS-213)

`DurableSessionStore::cite_investigation_source` connects the existing source hydrator to the
existing case owner. `SourceCitationTarget`, `SourceAcquisition`, `SourceCitationReceipt` and
`SourceCitationError` are re-exported from `coordination::investigations::evolution`.
These are reference Rust owner APIs, not a new public `fss/1` operation.

The bridge acquires actual original H3 object bytes through `PublishedSourceReader`, validates
`SourceObjectBinding::validate_response`, then attaches the verified payload digest to the exact
case/hypothesis/evidence side. Callers cannot construct an acquisition witness or submit an
arbitrary replacement case revision through this API. The result contains no footage or cursor.

## Admission and the two durable stages

The caller supplies authenticated principal/session authority, an exact alias, a current case
revision, a complete direct H3 request, the owning catalog/reader, and trusted runtime time.
Only H3 without downgrade or input continuation is accepted. A preview cannot be relabeled as
source. Source and case must have identical privacy classes, anchors and ContractBasis. A session
holding two privacy grants does not authorize copying evidence between those case domains.

Before source I/O, a side-effect-free case preflight executes on cloned state. It exercises the
real case owner's capability, mission, privacy, revision, hypothesis, deadline and capacity
checks. A stale target after a completed citation is refused before reading or charging again.
This preflight commits no clocks or revisions and cannot extend a lease or decision deadline.

The first durable stage is the existing `hydrate_from_source`: actual custody/closure/tombstone
checks, exact source/descriptor/artifact validation, full-vector quote admission and cumulative
session-token charging. It preserves narrowed request grants. Its existing refusal-side clock,
expiry, ambiguity and catalog behavior is unchanged.

The second stage commits the citation together with its acquisition provenance. It runs the
ordinary `Cite` state transition against the current head and writes one new, bounded journal
record. The witness binds the source/descriptor/publication/artifact/request/hydration-receipt
identities, principal/session/alias, observation time, quoted tokens and payload length, the
acquisition's journal/checkpoint roots, target predecessor and resulting case revision.
Source bytes are dropped before citation publication, never copied into the session journal.

These are **two commits**, not an atomic transaction across custody and cognition:

- A preflight refusal means acquisition was not started.
- An acquisition error uses the hydrator's existing refusal/indeterminate-charge semantics.
- Validation after hydration may leave a charge but never attaches an invalid response.
- A link error retains the successful acquisition witness; its citation may require journal
  reconciliation. The charge is not refunded and the source operation is not retried automatically.

After a process loss between stages, the charge can remain without a citation. No citation is
inferred from that charge. Inspect the case and the authorized journal root; any fresh acquisition
is a new bounded read and may be charged again. No source read executes during hot or cold replay.
An ambiguous link fences the existing shared owner just like work/case/evolution writes.

## What the source receipt proves, and what it does not

The source-specific receipt records that this runtime acquired the exact object under live
source authority before attributing it to a case. The reader is an explicitly trusted custody
boundary, not an implementation supplied by an untrusted agent. A bare ordinary `Cite` remains
a caller-attributed citation; it must not be presented as if it carried this source receipt.

Supporting versus contradicting is still an attributed cognitive choice. Source identity does
not establish whether that choice is correct. KnowledgeState and hypothesis disposition remain
unchanged. Inherited citations do not become applicable merely because their old bytes still
exist: `Cite` does not clear rebase barriers or replace an evidence owner's applicability receipt.
No source acquisition verifies a physical hypothesis, collapses a WorldEnvelope, dispatches a
probe/model, authenticates a transport, or grants effect authority.

## Replay, integrity and retention

The existing coordination record kind (`0x5743`) admits the explicitly new private domain
`fss.reference_source_citation_record.v1`. Its receipt and acquisition identities use separate
versioned domains. Old case, work, evolution, checkpoint and revision bytes are unchanged.
The private record has a hard 16 KiB ceiling, bounded text, fixed-width counters, qualified
hashes and canonical flags. Unknown/truncated/noncanonical input fails closed.

The common replay entrypoint verifies that every source link names the immediately preceding
journal root. A positive token charge must precede the link in a session-checkpoint record.
Replay checks its exact session checkpoint and alias binding, privacy, observed clock, charged
tokens, current case basis and predecessor, then re-executes the case owner and compares the
resulting revision/receipt and after-session fingerprints. No serialized case state is adopted.
These checks run before cold recovery can trim an incomplete suffix. A completed citation with
a lost acknowledgement cannot be rolled back to its acquisition root.

This is historical admission replay, **not independent re-verification of past I/O from hashes**.
The exact journal root must be independently trusted. The publication root and hydration receipt
are historical custody attestations made at live admission; the journal stores neither source
payloads nor complete source publication graphs. Deleted footage need not be resurrected to replay
a case. A later live acquisition always rechecks source availability and cannot use this receipt
as a source cache or disclosure grant. The journal/path still requires a protected sole writer.

## Regression coverage and qualification boundary

The tests cover actual published sources, exact support/counterevidence attribution, no source
bytes in the journal, stale retries, pre-I/O denial, privacy separation, substitution, revocation,
restart, all four append-failure phases at both stages, hot/cold recovery, partial completion at
capacity, deletion, rehashed false charge roots/aliases/revisions, and all truncated record prefixes.

```sh
cargo test -p fss-reference source_citation
cargo test -p fss-reference agent_session::checkpoint::journal
```

The editing environment has no Rust toolchain or usable network provisioning. The tests are
committed regression source, not executed qualification evidence. Compilation, Cargo tests,
rustfmt, clippy and full qualification remain required. Full public-envelope dispatch, durable
catalog continuations, measured full-request costs, asynchronous cancellation ownership and
production/multi-process qualification are not claimed by this reference bridge.
