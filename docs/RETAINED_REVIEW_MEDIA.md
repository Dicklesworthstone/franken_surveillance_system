# Retained screened review media

`fss-export review` turns an exact retained movie interval into a retained,
privacy-screened review artifact. It adds the local review step after approved
recording acquisition: native decoding, a separate grant for one recipient,
bounded validity, private file delivery, revocation, and deletion-aware custody.

This is the local portion of VIT-023 / FSS-068. The recipient is a local
`ContextAuthority` principal supplied by a trusted caller. The command does not
authenticate a remote reviewer, integrate FLDT, attest a payment-zone policy,
certify camera capture time, or publish a network download link. Those broader
requirements remain open.

## Artifact and authority

A request pins the retained import identity and root, sensor, half-open movie
tick interval, current mask-binding digest, recipient, purpose, validity
interval, and maximum media bytes. Native AVC or HEVC replay produces a timed,
uncompressed grayscale Matroska derivative. Existing privacy masks are applied
to the decoded pixels. Movie timing preserves presentation ordering, partial
frame trims, repeated edits, and explicit holes; a hole does not become a black
frame or a claim of absent activity. Unsupported decode paths refuse.

The retained root contains exactly the derivative media, its deterministic
render receipt, and a canonical review record containing the recipient grant.
The source root, manifest, originals, packet evidence, mask policy and selection
remain provenance dependencies. They are not copied into the derivative's
delivery closure. The receipt binds source identity, movie selection, native
decode results and work, timing, mask digest and generation, and media digest.
The review record separately binds the publishing authority and ledger basis.

Publication requires the existing export prepare/commit capabilities and media
read capability. Native review preparation does not write; the CLI opens an existing deployment through its normal recovery owner. The exact approval binds the
request, rendered content, grant, authority scope, and publication basis. The
publisher stages children, commits root reachability, and only then commits the
guarded review-grant transition. A root without that final transition cannot be
read through the review API. Retrying an interrupted publication verifies the
candidate graph and replays the renderer before admitting it. Repeating a
completed request reuses its root and grant.

The generic reference ledger append APIs reserve both review families and the
review object namespace. A caller cannot manufacture an active review grant by
appending a lookalike delta under another family.

## Local CLI workflow

Use an existing deployment. Obtain the exact import identity, retained root,
sensor, movie tick interval and current mask-binding digest from the retained source
inspection. Inspect the current mask binding with the existing operator command:

```bash
fss-event privacy-mask show \
  --root "$FSS_ROOT" --site "$FSS_SITE" --sensor "$SENSOR_ID"
```

Use the response's `privacy_mask.binding_digest` as `PRIVACY_DIGEST`. It includes
the exact binding, including the explicit no-policy marker; its generation is
also checked separately. A raw policy digest is not interchangeable with this
binding. Tick coordinates belong to that source's movie timeline; they are
not UTC timestamps. Keep a preceding UTC acquisition's uncertainty intact.

The following shell variables stand for inspected values and local policy
choices. The commands do not infer them:

```bash
review_args=(
  review
  --root "$FSS_ROOT" --site "$FSS_SITE"
  --import-identity "$IMPORT_ID"
  --expected-import-root "$IMPORT_ROOT"
  --sensor "$SENSOR_ID"
  --movie-start-tick "$START_TICK" --movie-end-tick "$END_TICK"
  --privacy-digest "$PRIVACY_DIGEST"
  --recipient "$REVIEWER_PRINCIPAL"
  --purpose 'Review the selected incident interval'
  --issued-at-ns "$ISSUED_AT_NS" --expires-at-ns "$EXPIRES_AT_NS"
  --max-media-bytes 67108864
  --principal "$OWNER_PRINCIPAL"
)
fss-export "${review_args[@]}"
```

Inspect the preview, then supply its exact approval digest with the same
arguments:

```bash
fss-export "${review_args[@]}" --approve "$REVIEW_APPROVAL"
fss-export review-show \
  --root "$FSS_ROOT" --site "$FSS_SITE" \
  --review-root "$REVIEW_ROOT" --principal "$OWNER_PRINCIPAL"
```

`review-show` reports metadata and whether the grant is revoked. Inspecting a
record does not authorize delivery. Delivery requires the exact recipient and
an explicitly attested current-time interval. Its earliest possible time must
be at or after issuance, and its latest possible time must be strictly before
expiry. A range crossing either boundary refuses.

Prepare a protected output directory and preview the separate file delivery:

```bash
install -d -m 700 ./review-delivery
read_args=(
  review-read
  --root "$FSS_ROOT" --site "$FSS_SITE"
  --review-root "$REVIEW_ROOT" --principal "$REVIEWER_PRINCIPAL"
  --attested-now-ns "$NOW_EARLIEST_NS:$NOW_LATEST_NS"
  --out ./review-delivery/incident.mkv
)
fss-export "${read_args[@]}"
fss-export "${read_args[@]}" --approve "$DELIVERY_APPROVAL"
```

The delivery approval binds the retained record and media digest, recipient,
site, original reader scope, current time interval, and exact output destination.
Delivery additionally requires the existing export-commit capability. The Linux
file owner holds the canonicalized protected parent directory and creates a new
private `0600` file outside the deployment. It refuses links, special files,
multiply linked files and directories writable by group or other users.

A durable attempt is recorded **before** creating the output. Completion requires
syncing the file and parent, reading every byte back through the held descriptor,
checking the exact length and media SHA-256, and revalidating the current grant,
source, privacy, deletion and destination state. The verified receipt retains
the file's device/inode and modification/change timestamps. It attests to that
local observation; it does not authenticate a remote recipient or guarantee that
the file remains present afterward.

### Inspecting and recovering a delivery

Save the `delivery_id` returned by preview or delivery. The identity binds the
site, recipient, retained review and media, and protected destination. It remains
stable when the caller supplies a new current-time interval. Approval still binds
that exact interval and reader authority, so changing either requires a fresh
preview.

| Durable state | Meaning | Safe behavior of the same delivery request |
|---|---|---|
| `not_started` | No matching attempt is in the ledger. | An approved request may exclusively create the destination. A preexisting file is refused. |
| `started_outcome_indeterminate` | An attempt is durable; the output may be absent, partial or complete. | Only an existing complete matching private file can be reconciled. Missing or partial output is refused and left unchanged. |
| `verified_local_file` | Complete local file verification was recorded. | A retry rereads the file and checks the retained identity and timestamps. It returns the existing receipt without writing another copy. |

A crash after file sync but before receipt publication can therefore be recovered
by previewing the same destination with a fresh valid time attestation and then
approving it. Success reports `private_file_reconciled` with
`file_written: false`. A completed retry reports `private_file_verified`.
Replacing, rewriting, linking, truncating or relaxing permissions on a previously
verified file refuses. An expired, revoked, deleted or privacy-invalidated grant
cannot authorize reconciliation even when the destination bytes match.

Inspect historical delivery state separately:

```bash
fss-export review-delivery-show \
  --root "$FSS_ROOT" --site "$FSS_SITE" \
  --delivery-id "$DELIVERY_ID" --principal "$REVIEWER_PRINCIPAL"
```

This command requires the exact recipient and media-read capability but does not
read the external file or authorize media access. It remains usable after grant
expiry, revocation and source/review deletion. It reports
`current_destination_verified: false`; a historical verified receipt is kept
distinct from a new observation of the destination.

Files created by an older version have no matching durable attempt and are not
adopted retrospectively. Generate a fresh delivery preview after upgrading;
older file-delivery approvals do not authorize the new lifecycle.

A missing or partial file never resets a recorded attempt. Removing a partial
file does not make the same attempt eligible to create another copy. Resolve an
indeterminate outcome explicitly; any separately approved delivery to another
destination has its own identity. The system does not infer that a missing file
was never delivered.

Revoke future deliveries with a separately approved transition:

```bash
revoke_args=(
  review-revoke
  --root "$FSS_ROOT" --site "$FSS_SITE"
  --review-root "$REVIEW_ROOT" --principal "$OWNER_PRINCIPAL"
)
fss-export "${revoke_args[@]}"
fss-export "${revoke_args[@]}" --approve "$REVOCATION_APPROVAL"
```

Repeated revocation is idempotent. Revocation prevents later managed reads; it
does not erase a copy already delivered to a recipient. Expiry is an access
condition, not an automatic physical deletion scheduler.

For an explicit cleanup after expiry, use the source-preserving
[`review-expiry-plan` / `review-expiry-commit` workflow](REVIEW_MEDIA_EXPIRY.md).
It selects certainly expired local derivatives, honors source holds, and keeps
original recordings and media still needed by current sibling reviews.
After approved cleanup, `review-show` reports retained audit metadata and the
deletion completion separately from explicit grant revocation.

## Current-source checks and deletion

Every managed read validates the durable review transition, exact reader,
current source import/root, current mask-binding digest and ledger generation,
committed deletion state, byte allowance and attested time interval. Final
release checks these conditions again. Both the source import and derivative
must still have their exact durable root records on disk; cached publisher
visibility cannot authorize a read after either record is lost or corrupted.
A mask change invalidates an older
derivative even if its retained pixels are still available. Narrowing the
reader's byte allowance also prevents release of a previously loaded clip.

Delivery rechecks the source's retained metadata and authority and hashes the
derivative bytes and receipt. It does not reread every original source payload;
complete native source verification occurs during rendering. The retained
derivative is a separate delivery closure. Metadata inspection can still explain
an existing grant after source-root damage, but cannot authorize media delivery.

The source import and review root participate in the existing deletion graph.
A committed source-deletion plan denies review access before the unlink phase
finishes. The graph includes the review root, media, render receipt and grant
record, so source cleanup cannot leave an authorized derivative outside that
closure. Revocation remains distinct from deletion.

Delivery attempt and verification records retain audit metadata only. Their
ledger children do not retain the review root, derivative media or original
source bytes. Source deletion and explicit expired-review cleanup can therefore
remove footage while preserving the recipient's historical delivery state.

## Bounds and evidence limits

The current profile is bounded to 64 MiB of retained derivative media, 1,024
presentation occurrences and 1,024 aggregate prerequisite native pictures,
dimensions no larger than 4,096 on either axis and 4,194,304 pixels, and an 8 MiB render receipt. Native source reads, complete
origin verification, decoder work and cached luma have independent cumulative
limits. The original MP4 must fit the 128 MiB native admission bound even for
a shorter requested interval. Rendering and its final source verification share
one cumulative request budget; delivery separately checks the current reader
allowance. Raw grayscale
output can reach the byte bound quickly; this profile is for short review
intervals. It does not add color, audio, video compression, transcoding through
an external runtime, or support for codecs outside the native paths.

An all-hole selection, missing native frame, unsupported decode operation,
changed source, stale approval, wrong recipient, out-of-range time, revoked
grant, committed deletion or exhausted budget refuses. No result upgrades an
unknown source time, gap or privacy attestation into a positive claim.

Implementation entry points are `fss_reference::review_media`, its `grant`,
`record`, `render`, `storage` and `delivery` modules, and
`crates/fss-cli/src/bin/fss-export/review`. Contract coverage uses actual AVC and
HEVC fixtures, decoded mask pixels, cold reopen, interrupted publication,
forged candidate roots, recipient/time restrictions, revocation and deletion.
See `IMPLEMENTATION_STATUS.md` for the actual validation result of this session;
the existence of a test is not a qualification claim.
