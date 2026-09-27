# Redacted event evidence export

Status: implemented reference behavior; not production-qualified.

`fss-export event` implements the registered P5 export prepare/commit contract for one exact
current event revision. It publishes a new export root and authority record; it never exposes the
live archive namespace and performs no network delivery.

## Preview and commit

First read the event's current revision digest with the existing event/review tooling. Preview:

```sh
fss-export event --root "$ROOT" --site "$SITE" --event-id "$EVENT" \
  --expected-revision "$REVISION" --recipient 'recipient:insurer-case-7' \
  --purpose 'Owner-authorized incident review' --expires-at-ns "$EXPIRY_NS"
```

Preview writes nothing. Review the returned `package`, `export_root`, and
`approval_digest`. Repeat the exact command with `--approve "$APPROVAL"` to commit.

The fixed profile `event-summary-redacted-v1` includes event lifecycle state/class, conservative
capture interval and uncertainty text, probability bounds, evidence/model digests, hashed failure
domains, decision fingerprints, and zone/track counts. It deliberately excludes raw media,
source/device identities, zone names, track identities, model tensors, and failure-domain plaintext.
There is no `--raw`, `--include-all`, or override mode.

The manifest's only child is the redacted export record. Event/source roots named inside the record
are metadata references, not manifest children, so the export root cannot be used as a capability
to traverse the live archive namespace.

## Authority and recovery

`CAP-EXPORT-PREPARE-001` is read-only. `CAP-EXPORT-COMMIT-001` commits only the exact approved
record. The `evidence_export` ledger family is reserved to the guarded export writer, preventing
generic authority appends from fabricating an export.

Commit publishes the redacted root first and its reserved authority delta second. If execution is
interrupted after root publication but before the authority append, the exact approved request can
be retried; an already committed exact request is idempotent. A changed current event revision
requires a new preview and approval.

`--expires-at-ns` is retained export-policy metadata. This reference path does not claim a trusted
wall clock, automatic expiry deletion, recipient authentication, or provider delivery. No external
transport is performed.

## Verification

```sh
cargo test -p fss-reference --lib evidence_export
cargo test -p fss-reference --test evidence_export_contract
cargo test -p fss-cli --bin fss-export
```

These are reference contracts over synthetic event evidence. They do not establish detection
quality, production chain-of-custody controls, legal sufficiency, or remote-recipient security.
