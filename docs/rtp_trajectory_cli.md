# Export and replay-verify anonymous RTP trajectories

`fss-decode-rtp track-stream` exposes the existing canonical trajectory stream.
`verify-tracks` reproduces it from current retained RTP custody and the independently
selected, verified neural package. This adds an operator path to the native
`write_tracking_stream` / `verify_tracking_stream` implementation; it does not
introduce another tracker, serialization, decoder, or authority plane.

## Export

Use the same source, package, class, decoding and tracking options as `track`:

```sh
fss-decode-rtp track-stream \
  --root "$DEPLOYMENT" --site "$SITE" --source-root "$SOURCE_ROOT" \
  --custody current \
  --package "$PACKAGE" --package-sha256 "$PACKAGE_SHA256" --class-index 0 \
  --tracks-out "$NEW_TRAJECTORY_FILE"
```

The destination must be new, private and outside the deployment. The command uses
the existing private-output owner, rechecks its path at I/O boundaries and syncs
both file and directory before reporting `tracks_export_complete=true` or the
final `tracks_sha256`. Failed admission does not initialize a replacement source
store. A later failure can leave a partial export; preserve it and retry at a new
filename rather than overwriting it or treating its bytes as a complete transcript.

The canonical binary stream includes source progress, native frame receipts,
head dispositions, observed anonymous track assignments, linked frame identities,
and terminal native/detector/tracker accounting. Coasting predictions are not
recorded as observations. Neither physical identities nor absence are certified.

## Verify after a restart

Retain the export's digest independently, as well as the original source and exact
local package. Repeat the original numerical policies, bounds and completion mode:

```sh
fss-decode-rtp verify-tracks \
  --root "$DEPLOYMENT" --site "$SITE" --source-root "$SOURCE_ROOT" \
  --custody current \
  --package "$PACKAGE" --package-sha256 "$PACKAGE_SHA256" --class-index 0 \
  --tracks-in "$TRAJECTORY_FILE" --tracks-sha256 "$SAVED_TRAJECTORY_SHA256"
```

Verification reads a bounded regular file, then executes the existing native
reproducer and compares every byte and final EOF. A digest recomputed over altered
bytes is insufficient. Saved lengths never allocate decoder buffers, saved labels
never select a class, and saved metadata never select the source or package.
There is no pixel output, JSON report output, source publication or camera input.
Current privacy and deletion/custody checks still apply; an old unmasked transcript
cannot override a new mask or substitute for missing originals.

Successful verification reports `tracks_verified=true`. File verification does
not promise future source retrievability or activate any effect authority.

## Separate completion meanings

The default `--completion complete` requires complete source, inference and
association. Explicit `--completion diagnostic` permits a fully enumerated source
refusal history, but still requires actual delivered frames and complete analysis
of all delivered frames. It cannot waive inference, tracking, cancellation or
resource failures.

`tracks_export_complete` / `tracks_verified` describe the portable transcript.
`tracking_complete` describes the native source-and-analysis result. A verified
diagnostic transcript retains `tracking_complete=false` when source gaps exist.
Changing completion mode, class, numerical settings or bound values changes the
requested transcript; repeat the originals exactly rather than interpreting a
verification refusal as permission to relax them.

## Resource contract

The ordinary source, decoder, custody and tracker limits remain in force. The
separate transcript limits are:

| Option | Default | Accepted range |
| --- | --- | --- |
| `--max-tracks-bytes` | 64 MiB | 1 byte through 256 MiB |
| `--max-track-record-bytes` | 16 MiB | 1 byte through 16 MiB |
| `--max-track-records` | 1,000,002 | 3 through 5,000,002 |

Native record admission, encoding quotes, bounded short I/O and interrupted-call
handling are reused without reinterpretation. Verification performs fresh native
inference and tracking, so its cost is not merely hashing the saved file. Original
RTP time remains untrusted media time, not physical capture time. This interface is
for exhaustive native tracking; sparse cascade skips are not empty detections and
are not silently fed into this tracker.

## Regression scope

Five parser cases cover required independent inputs, mode isolation, duplicates,
resource bounds and explicit diagnostic selection. Eight real-process contracts
cover cold deterministic/private round trips, tampering with recomputed digests,
changed policies, unsafe paths, missing originals, valid new privacy masks,
diagnostic source gaps, and independent limits. The native privacy regression now
uses dimensions obtained from actual decoding, and a separate regression retains
the refusal for an incompatible 1x1 mask. No production privacy check is weakened.

The sampled-tracking miss fixture also distinguishes tentative-track deletion from
confirmed-track coasting, then checks that intentional skips do not add misses or
refill admission budgets. The numerical tracker and sampling behavior are unchanged.
Its source-pinned sampled recipe changes with the test-bearing source revision;
this does not change exhaustive trajectory stream encoding or tracker policy.

Native execution of these new commands and tests is not yet confirmed at publication.
The authoring environment has no Rust compiler. These changes do not constitute
field, performance, platform or release qualification. The corrected and additional
native trajectory regressions remain in the existing entrypoint, alongside all
prior detection, sampled-tracking and process contracts:

```sh
bash scripts/check_rtp_tracking.sh
```
