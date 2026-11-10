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
inspection. Use `current_mask(...).digest()` for the mask binding, including
its generation or explicit no-policy marker; a raw policy digest is not
interchangeable with this binding. Tick coordinates belong to that source's movie timeline; they are
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
site, time interval, and exact output destination. The Linux file writer holds
the canonicalized protected parent directory, rejects a symlink or existing output filename,
and creates a private `0600` file outside the deployment. It checks retained
authority before release and during finalization. Existing files are never
silently overwritten. An interrupted write can leave a partial private file; inspect or remove that file explicitly before attempting delivery to the same destination.

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

## Current-source checks and deletion

Every managed read validates the durable review transition, exact reader,
current source import/root, current mask-binding digest and ledger generation,
committed deletion state, byte allowance and attested time interval. Final
release checks these conditions again. A mask change invalidates an older
derivative even if its retained pixels are still available. Narrowing the
reader's byte allowance also prevents release of a previously loaded clip.

The source import and review root participate in the existing deletion graph.
A committed source-deletion plan denies review access before the unlink phase
finishes. The graph includes the review root, media, render receipt and grant
record, so source cleanup cannot leave an authorized derivative outside that
closure. Revocation remains distinct from deletion.

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
`record`, `render` and `storage` modules, and
`crates/fss-cli/src/bin/fss-export/review`. Contract coverage uses actual AVC and
HEVC fixtures, decoded mask pixels, cold reopen, interrupted publication,
forged candidate roots, recipient/time restrictions, revocation and deletion.
See `IMPLEMENTATION_STATUS.md` for the actual validation result of this session;
the existence of a test is not a qualification claim.
