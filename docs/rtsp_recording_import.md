# Import a retained RTSP recording without losing its source evidence

`fss-import-rtsp` converts one exact durable native H.264 or H.265 recording window into a
completed retained file import. The destination keeps the original recording manifest, RTP
source pack, packet-to-NAL-to-MP4 index, initialization segment and media fragment, alongside
the combined MP4 and its native sample/timing metadata. Decode and analysis can therefore
verify their source ancestry after the capture archive is offline.

This is a bounded, offline reference composition. It opens no camera connection and does not
resume capture. It neither publishes an event nor dispatches an alert. It is not a release or
a live-camera qualification.

## Select and review the exact recording

Use a durable window slot and root returned by the native RTSP recording publisher. Supply
that recording's exact sensor, stream, generation, authority anchor and receive-clock identity.
The importer does not search the archive or select a latest window.

```sh
fss-import-rtsp \
  --archive /path/to/rtsp-archive \
  --root /path/to/deployment --site site:home \
  --window-slot "${WINDOW_SLOT:?supply the durable window slot}" \
  --window-root "${WINDOW_ROOT:?supply its exact SHA-256 root}" \
  --codec avc \
  --sensor-id sensor:porch --stream-id stream:porch --generation 1 \
  --anchor "${SOURCE_ANCHOR:?supply the recording authority anchor}" \
  --receive-clock "${RECEIVE_CLOCK:?supply the recording clock identity}" \
  --receive-time-ns 5000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Choose `--codec hevc` for a native H.265 recording. There is no codec fallback. An incorrect
root, slot, scope, codec, deleted child, damaged packet or inconsistent remux mapping refuses
the import.

Without `--approve`, the command emits one JSON plan without filesystem, clock or network
I/O. Its `approval_digest` binds the complete source selection, paths, site, principal,
receive-time declaration, optional capture origin and every resource ceiling. Rerun the same
command with `--approve sha256:PLAN` after reviewing the plan. A mismatched approval is refused
before filesystem access. Owner authorization, reading originals and retaining originals are
three required explicit acknowledgements.

Both paths must be absolute, distinct and non-nested. The archive must already have its
publisher layout; a missing archive is never created. Execution acquires its existing exclusive
publisher lock and can complete normal publication recovery. The destination parent must
exist. Source and destination aliases are checked using their canonical parent paths before
opening the destination.

## Capture origin and presentation timing

The recording's native MP4 presentation timestamps determine each sample's relative time,
including composition offsets. RTP ticks and packet receive times do not establish UTC or
a physical capture origin.

Without an explicit capture origin, retained capsules have unknown capture time. To use this
recording for time-dependent watch or corroboration, add both:

```sh
--capture-start-ns 1000000000 --capture-uncertainty-ns 1000000
```

The start is the operator's declared capture time for the window's earliest presentation sample. The uncertainty
remains attached to the reconstructed intervals and the label remains `operator_assumption`.
No `--fps` option is accepted: a nominal frame rate must not replace retained MP4 timing.
Receive time and capture start accept nonnegative signed-128-bit nanoseconds; capture
uncertainty accepts unsigned-64-bit nanoseconds. Overflow is refused.

## Use the completed destination import

Success emits `import_identity`, `import_root`, `manifest_digest`, `origin_proof`, the
selected window root, codec, frame count, capture-time label and an exact-retry `reused` flag.
The `origin_proof` binds the owner request and original recording representation into the
file import's retained closure.

The existing media commands consume the returned identity:

```sh
fss-file verify \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed retained import identity}"

fss-file decode \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed retained import identity}" \
  --segment 0 --segment-count 4 --interpretation ycbcr
```

Choose an actual retained range. H.264 decoding starts at an IDR; H.265 decoding starts at an
admitted IRAP. Native decoding preserves display order. The existing model-free motion,
[whole-recording watch](long_recording_watch.md) and
[two-camera corroboration](long_recording_corroboration.md) paths also consume the import.
Their independent source, decoder, timing, geometry and approval rules still apply.

Every downstream original-source access checks the retained RTSP provenance. Native mapping
verification is cached only within the current read handle, under its bound; it does not turn
a prior process's verified flag into current source authority. Current destination sensor
privacy masks apply before decoded pixels reach a consumer or export. This workflow retains
unencrypted original media locally; it does not claim encrypted custody or a remote archive.

## Bounds and interrupted imports

| Option | Default and hard ceiling | Meaning |
|---|---:|---|
| `--max-frames` | 256 | Complete native recording samples; no truncation |
| `--max-original-bytes` | 33,554,432 | Original recording closure, including its manifest and four children |
| `--max-media-bytes` | 33,554,432 | Combined MP4, independently bounded |
| `--max-work` | 1,000,000,000,000 default; 1,000,000,000,000,000 maximum | Cumulative caller reservation for the bounded import |
| `--timeout-ms` | 30,000 default; 600,000 maximum | Cooperative deadline at custody boundaries |

Original and media ceilings are independent. Narrower owner ceilings are enforced against
the complete recording and combined media; an oversized window is refused whole. The source
loader has an independent 32 MiB hard limit. Reservations do not refill between source reads,
verification or destination publication. A single bounded native verifier is not preempted
inside its synchronous work.

A crash or output failure may leave staged objects, a published root or completed authority.
Rerun the exact approved request to reconcile that state. A completed exact retry returns the
same identities with `reused: true` without appending duplicate import authority or effects.
Changed selection, timing or limits is a new request, not a repair of the old import.
Conflicting or damaged committed evidence is refused.

Retry still requires the selected original archive to be available and verified. Once the
import is complete, subsequent destination verification, decode and analysis need only the
retained destination closure. This separation makes the import's source check repeatable while
allowing independent offline use of completed custody.

## Focused validation

The new native regression families exercise AVC and HEVC source preservation, refusal paths,
publication/reopen and exact retry. The real-binary HEVC workflow also covers taking the source
archive offline and invoking `fss-file verify` and `decode` from destination custody.

```sh
cargo test -p fss-reference --test rtsp_import_contract
cargo test -p fss-cli --bin fss-import-rtsp --test rtsp_import_cli
```

These new targets were prepared and source-reviewed during an execution-environment outage;
they have not yet been compiled or executed in this session. Existing codec qualification and
older test results do not substitute for running these new integration cases.
