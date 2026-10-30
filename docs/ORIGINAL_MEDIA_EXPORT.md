# Event-linked original footage export

`fss-export media` exports the verified retained recording behind a current native or reviewed event. The
package contains the exact playable source, a canonical custody record and their shared manifest
root. A recipient can verify the files without the deployment or the original input file.

The `event-original-media-whole-source-v1` profile supports original revision-one long-watch,
long-dwell and long-corroboration events. Verified operator-reviewed successors use the separate
`event-reviewed-original-media-whole-source-v2` profile. A corroboration export includes **one explicitly
selected source**, and reports the excluded camera count. Supported media are omission-free MJPEG
and video-only AVC/HEVC MP4 created by the native RTSP window/catalog/page import owners. Generic
MP4 imports can contain unexamined audio or other tracks and are refused. The selected source is
limited to 64 MiB and 16,384 source capsules.

Current native detector-package candidates use
`event-package-original-media-whole-source-v3`. This connects retained `package-detect` results,
approved package-track events and their original footage to the same export and independent
verification workflow. The export verifies the event's complete authoritative history, exact
retained detector/tracker analysis, source capsules and provenance graph without running inference
again. Loose source, model and report files are unnecessary after retention.

Package candidates keep their unclassified, indeterminate and uncalibrated interpretation. The
version-three record binds the package-event provenance root and the retained detector-analysis
root separately from the selected recording. It does not turn a class score into a confirmed
event, absence claim or alert authority. Current operator-reviewed package events use the separate
`event-reviewed-package-original-media-whole-source-v4` profile. It verifies the complete retained
review chain and the exact original package computation, preserving the native candidate's
uncertainty alongside the operator's current lifecycle decision. Reviewed long events keep their
version-two path.

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

An operator can investigate, resolve or reject a native long or trained-package event with `fss-review`, then export its
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

The version-two and version-four custody records distinguish the current reviewed revision from the original
native event and records the ordered review and statement roots, revision identities, authority
anchors and dispositions. Reviews remain explicitly labelled operator assertions. Reviewer names
and reason text are not disclosed by this profile. Inspection of the original source computation
does not claim that a native model reproduced the operator's lifecycle decision. A version-four
record additionally identifies the unchanged native package origin as indeterminate, unclassified
and uncalibrated. Its `event_provenance_root` and `analysis_roots` remain the original package proof
and retained detector root; each operator statement has its own separate pins in `review_chain`.
A resolved or rejected review adds no sensor support, calibration, class confirmation or alert
authority. The native `PackageEvent::open` reader still refuses a reviewed successor; only the
complete verified review chain can authorize inspection of that exact historical origin.

Approval binds the reviewed record as well as the exact source bytes. A later review, privacy
change or deletion invalidates the prepared output. Offline verification checks the versioned
record and package against the trusted export root; it cannot determine whether a newer review
exists in a deployment it does not open. Existing version-one, version-two and version-three
canonical records, display records and package roots retain their original interpretation.

## Source custody and publication

The source must belong to the exact retained computation that produced the original native event;
reviewed exports additionally prove the complete chain to its current successor. The
existing event/source owners verify original native analysis roots, completed import authority,
capsule identity, deletion state and current privacy. Native RTSP imports additionally verify the
original packet/wire custody that produced the retained MP4. Whole-source reconstruction checks
every chunk and the complete source digest. A masked camera has no unredacted override.

For native and reviewed package events, `--import-identity` and `--expected-import-root` must equal the selected
retained detection's original source pins. Substituting another recording from the same camera is
refused. Corrupt or missing detector, tracking or source proof also refuses both a fresh preview
and final release of an already approved output. A reviewed package export also checks every
intermediate review statement, not just the latest decision. Version-four records and manifest
profiles cannot be substituted for any earlier profile or stripped of their review lineage.

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

Package-event cases cover cold export of exact whole-source bytes, explicit uncertainty, profile
round trips and downgrade refusal, wrong source/revision pins, missing source and analysis custody,
privacy/deletion/review invalidation, and the real CLI preview → approved write → exact retry →
deployment-independent verification sequence. Each synthetic fixture performs one native package
inference to establish retained input; export and verification perform none.

Reviewed-package cases additionally cover cold multi-review recovery, each original/native and
operator proof pin, current source and destination binding, stale native and intermediate-review
approvals, review corruption and cancellation, forged native probability changes, and fresh
privacy/deletion refusal. The real CLI regression reviews the retained candidate, refuses lost
earlier review custody without creating output, exports the current version-four package, retries
exactly, then verifies it after the deployment is moved offline.
