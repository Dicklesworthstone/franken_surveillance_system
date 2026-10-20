# Event-linked original footage export

`fss-export media` exports the verified retained recording behind a current native event. The
package contains the exact playable source, a canonical custody record and their shared manifest
root. A recipient can verify the files without the deployment or the original input file.

The `event-original-media-whole-source-v1` profile supports original revision-one long-watch,
long-dwell and long-corroboration events. Verified operator-reviewed successors use the separate
`event-reviewed-original-media-whole-source-v2` profile. A corroboration export includes **one explicitly
selected source**, and reports the excluded camera count. Supported media are omission-free MJPEG
and video-only AVC/HEVC MP4 created by the native RTSP window/catalog/page import owners. Generic
MP4 imports can contain unexamined audio or other tracks and are refused. The selected source is
limited to 64 MiB and 16,384 source capsules.

## Preview and approve

Choose the exact current event revision and one of its retained imports. The import root must
come from the retained import's verified metadata, not an unrelated recording. Choose an existing
destination parent outside the deployment that is not writable by group or other users.

```sh
fss-export media --root "$ROOT" --site "$SITE" \
  --event-id "$EVENT" --expected-revision "$REVISION" \
  --import-identity "$IMPORT" --expected-import-root "$IMPORT_ROOT" \
  --recipient 'recipient:owner-case-7' --purpose 'Owner incident review' \
  --expires-at-ns "$EXPIRY_NS" --attested-now-ns "$EARLIEST_NS:$LATEST_NS" \
  --whole-source yes --max-source-bytes 67108864 --out "$OUTPUT_DIR"
```

The preview creates no output directory. Review `record`, `media_bytes`, `media_digest`,
`export_root` and `approval_digest`. **The entire selected recording is included**, including
frames before and after the event. There is no trimming, masking, transcoding or multi-camera
concatenation. The source capture bounds, event bounds, capture-time assumptions, exact source and
analysis identities, and exclusion of other corroborating sources are disclosed in the record.

Repeat the exact command with `--approve "$APPROVAL"`. Approval binds the current deployment
anchor, event revision, source root, principal, recipient, purpose, exclusive expiry, caller-attested
current-time bounds, byte ceiling and actual destination parent identity. Moving the destination
or replacing its parent requires a new preview. Both attested time bounds must precede expiry;
the command never silently substitutes the host clock.

The explicitly invoked local-owner adapter supplies the existing `CAP-READ-MEDIA-001` capability
in addition to export authority. Metadata export authority alone cannot disclose footage. Library
callers must supply that separately registered media-read grant and export prepare authority;
publication additionally requires export commit authority and the exact approval. `fss-export event`
continues to export only redacted metadata. No capability registry generation is reinterpreted.
If a library caller supplies an authority deadline, the complete attested time interval must also
precede that deadline at preview, approval and final revalidation, independently of package expiry.

## Export a reviewed incident

An operator can investigate, resolve or reject a native event with `fss-review`, then export its
original recording with the same `fss-export media` command. Use the **current reviewed revision**
as `--expected-revision`; an approval obtained before review is stale. No extra source-read or
export authority is implied by the review itself.

The export owner verifies the complete ordered review chain back to the original native event.
Each successor must be exactly the event that its retained operator statement derives from its
predecessor. Source evidence, model receipts, classification, probability, capture bounds and
sensor-integrity uncertainty remain subject to the existing review invariants. Missing, altered,
unsupported or excessive review history refuses export; the command never silently skips a link.
The complete chain is bounded to 255 reviews. Event history is capped at 32 MiB, combined lineage
read reservations at 64 MiB, and the complete exported custody record at 128 KiB.

The version-two custody record distinguishes the current reviewed revision from the original
native event and records the ordered review and statement roots, revision identities, authority
anchors and dispositions. Reviews remain explicitly labelled operator assertions. Reviewer names
and reason text are not disclosed by this profile. Inspection of the original source computation
does not claim that a native model reproduced the operator's lifecycle decision.

Approval binds the reviewed record as well as the exact source bytes. A later review, privacy
change or deletion invalidates the prepared output. Offline verification checks the versioned
record and package against the trusted export root; it cannot determine whether a newer review
exists in a deployment it does not open. Existing version-one canonical records, display records
and package roots retain their original interpretation.

## Source custody and publication

The source must belong to the exact retained computation that produced the original native event;
reviewed exports additionally prove the complete chain to its current successor. The
existing event/source owners verify original native analysis roots, completed import authority,
capsule identity, deletion state and current privacy. Native RTSP imports additionally verify the
original packet/wire custody that produced the retained MP4. Whole-source reconstruction checks
every chunk and the complete source digest. A masked camera has no unredacted override.

The command holds the deployment's exclusive lease throughout preparation and output. Before
publishing completion it rechecks the current event, import, privacy and complete source through
that owner. A second process cannot commit a compliant privacy or deletion change during release.
The filesystem writer pins the output parent and package directory by open descriptors, writes
create-only files, syncs them, and reads back their exact bytes before creating the completion name.

New output directories use mode 0700 and files mode 0600. This adapter requires Linux x86-64 or
aarch64 and `/proc/self/fd`. Its final package is:

| File | Meaning |
|---|---|
| `source.mp4` or `source.mjpeg` | Exact selected retained video source |
| `record.canonical` | Canonical event/source/disclosure custody record |
| `manifest.canonical` | Manifest binding that record and the source bytes |
| `record.json` | Human-readable projection, checked against the canonical record |
| `COMPLETE.json` | Final completion descriptor, published only after verification |

`COMPLETE.json.pending` may also remain as a redundant hard link to the completion descriptor.
It is not a completion signal. No deployment export-complete authority row is written before or
after the file copy, and the command does not claim delivery to a recipient or create another
retained media replica in the deployment.

An exact complete retry verifies all bytes and reports `already_exported_original_media` without
overwriting. Extra objects, altered files, symlinks and incomplete directories are refused. A
cancelled or failed write can leave a private partial directory without `COMPLETE.json`. A failure
after completion becomes visible is reported as indeterminate; verify the output before retrying.
The command never deletes or overwrites unrelated destination content to make progress.

## Verify a received package offline

Pass the root through an independent trusted channel; a root copied out of an untrusted package
does not authenticate its contents.

```sh
fss-export media-verify --input "$OUTPUT_DIR" --export-root "$TRUSTED_EXPORT_ROOT" \
  --recipient 'recipient:owner-case-7' --attested-now-ns "$EARLIEST_NS:$LATEST_NS"
```

Verification checks manifest closure, canonical record encoding, exact source bytes, completion
descriptor and display projection. It also checks the requested recipient label and a fresh
caller-attested interval against exclusive expiry. It opens no deployment and performs no network
request. Hash verification is not a signature, recipient authentication, scene-truth claim,
current-privacy check or delivery proof. Copies are plaintext; later expiry, masking or source
deletion cannot erase copies that have already been exported.

## Focused regression targets

```sh
cargo test --locked --offline -p fss-reference --test original_media_export_contract
cargo test --locked --offline -p fss-cli --bin fss-export --bin fss-review --test rtsp_event_media_export_cli
```

These exercise native retained event/source custody, exact approvals, scope/clock/byte boundaries,
privacy and deletion invalidation, corruption, cancellation, create-only output, process restart
and offline verification. Reviewed-event cases cover native AVC, HEVC and MJPEG, multi-review
chains, stale approvals, missing or corrupt review custody, private rationale redaction, and
continued refusal to replay an operator decision as native model output. They do not qualify detector accuracy or arbitrary camera/browser codec
profiles. This implementation advances FSS-068; broader incident clip editing and multi-camera
handoff remain separate work.
