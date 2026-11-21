# Redacted event evidence export

Status: implemented reference behavior; not production-qualified.

`fss-export event` implements the registered P5 export prepare/commit contract for one exact
current event revision. It publishes a new export root and authority record; it never exposes the
live archive namespace and performs no network delivery.

For playable footage, use the separately approved [`fss-export media` whole-source profile](ORIGINAL_MEDIA_EXPORT.md).
The redacted event profile and its existing wire format remain unchanged.

## Preview and commit

First read the event's current revision digest with the existing event/review tooling. Preview:

```sh
fss-export event --root "$ROOT" --site "$SITE" --event-id "$EVENT" \
  --expected-revision "$REVISION" --recipient 'recipient:insurer-case-7' \
  --purpose 'Owner-authorized incident review' --expires-at-ns "$EXPIRY_NS"
```

Preview publishes no new export. Review the returned `package`, `export_root`, and
`approval_digest`. Repeat the exact command with `--approve "$APPROVAL"` to commit. This
preview uses one immutable retained owner and can run while capture holds the writer. It
does not initialize a deployment, acquire its writer lock, repair journals or reconcile effects.
It verifies the complete canonical event lineage, including revision-witness custody, without
opening original media or model payloads. Missing or incomplete authority/effect journals refuse
the preview; they are never reconstructed by this read path.

The complete response, including the approval digest, remains buffered until the opening snapshot,
selected payloads, publications and deletion state have been revalidated. A concurrent authority
advance or custody change refuses the result; retry against a stable committed snapshot. Approved
publication retains the existing exclusive writer, restart reconciliation and exact-approval checks.

The fixed profile `event-summary-redacted-v1` includes event lifecycle state/class, conservative
capture interval and uncertainty text, probability bounds, evidence/model digests, hashed failure
domains, decision fingerprints, and zone/track counts. It deliberately excludes raw media,
source/device identities, zone names, track identities, model tensors, and failure-domain plaintext.
There is no `--raw`, `--include-all`, or override mode.

The manifest's only child is the redacted export record. Event/source roots named inside the record
are metadata references, not manifest children, so the export root cannot be used as a capability
to traverse the live archive namespace.

## Verified readback

After commit or process restart, verify the exact committed export from retained authority rather
than trusting previously emitted terminal output:

```sh
fss-export show --root "$ROOT" --site "$SITE" --export-root "$EXPORT_ROOT"
```

Readback requires prepare/read authority only. It verifies the reserved `evidence_export` delta,
its generation and object namespace, the root manifest's one-child redaction closure, the canonical
record bytes, and the record-derived root/object identities. It opens an immutable retained owner
without taking the writer lock, repairing journals, or creating deployment files. An active writer
can remain open. Missing roots, incomplete journals, deleted custody, and missing, duplicated,
altered or noncanonical records are refused without partial output. Raw evidence and model
payloads remain unopened; their unavailability does not prevent redacted export inspection.

The optional read bounds apply to `show` and unapproved `event` previews:

| Option | Default | Maximum |
|---|---:|---:|
| `--max-read-bytes` | `67108864` (64 MiB) | `1073741824` (1 GiB) |
| `--max-read-objects` | `65536` | `1000000` |
| `--timeout-ms` | `30000` | `600000` |

Values must be positive decimal integers without signs or leading zeros. One nonrenewing
allowance covers deployment metadata, canonical event lineage or redacted export payloads,
publication records and all final rereads. Object counts measure payload read attempts, not
filesystem syscalls. The cooperative deadline is checked at native read boundaries.

Before releasing the complete JSON report, `show` rehashes the selected objects, checks publication
and deletion state again, and verifies that the layout and both journal roots still match the
opening authority. A concurrent authority change or exhausted allowance refuses the result. The
report is at most 1 MiB and includes `deployment_mutated: false`, `payload_read_bytes`, and
`payload_read_attempts`; the usage includes final revalidation. The export root, record digest,
redaction profile and canonical package bytes are unchanged.

Approved `event` requests reject these preview-only flags. Both paths keep the same canonical
record, export root and approval identity. [`fss-export-package pack`](portable_export_packages.md)
has its own immutable preview controls; its approved file copy keeps the exclusive publication path.

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
cargo test -p fss-cli --test export_package_cli show::
```

Fresh-preview regressions cover exact native approval/report parity beside a held writer,
prepare-only authority, unavailable source/model payloads, complete cumulative budgets,
late metadata/witness/custody changes, cancellation and refusal without journal repair.
Reviewed whole-source exports also reserve every canonical lineage and witness reread
before returning their export pins.

These are reference contracts over synthetic event evidence. They do not establish detection
quality, production chain-of-custody controls, legal sufficiency, or remote-recipient security.
