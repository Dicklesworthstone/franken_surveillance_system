# Select one retained native video frame

`fss-video publish --output-index N` retains one display output from an explicitly selected AVC or HEVC source range. It uses the existing native decoder, source verification, privacy policy and frame publication owner. Other frames are decoded but not published.

```sh
fss-video publish \
  --root /absolute/deployment --site site:example \
  --import-id "${IMPORT_ID:?supply a completed retained import}" \
  --codec hevc --privacy-policy none \
  --read-originals yes --retain-derived yes \
  --first-segment 0 --segment-count 8 --output-index 1
```

Supply the actual codec and current privacy-policy digest; `none` is valid only when no policy is declared. The range must start at native random access (AVC IDR or an admitted HEVC IRAP). The initial invocation is a pure JSON preview. Repeat with its exact `--approve` digest to execute. Selection, original range, effective decoder settings, privacy and all budgets are bound into the approval. Different display positions and all-frame requests cannot reuse that approval.

`N` is a zero-based display position within the requested range, not an absolute source segment. B-picture reordering can make display and source positions differ. HEVC RASL omissions remain explicit; a missing requested output is refused rather than replaced with another picture.

## Validation and custody

The entire native range must finish successfully before the selected frame enters publication. A later decode failure, absent selected output, cancellation, expired cooperative deadline or exhausted decode allowance prevents publication of an accepted prefix. The derived allowance is checked before publication too.

Every source unit consumes the same cumulative `encoded_bytes_plus_coded_luma_capacity.v1` decode budget, including decode-ahead, skipped units and parameter sets. Only the selected frame consumes derived-byte admission: its planes, native receipt and the existing 4096-byte manifest reservation, including exact reuse. Selection never renews an allowance.

The selection layer holds at most the chosen frame plus the current output. Native reference/reordering buffers, source verification and publication allocations remain separately owned; this is not a measured peak-memory claim or a constant-memory claim for the whole operation. The existing 1024-source-unit CLI bound is unchanged.

The selected frame keeps exactly the identity it would have had under all-frame publication over the same range. Existing `fss-video read` and `verify` work with its root without new receipt formats. Read verifies retained consistency and current source/privacy admission without decoding. Verify recomputes the entire original range, even after matching the chosen output, and compares the exact receipt and all three planes.

## Reports and retry

Successful execution emits one `frame`, a `selection` report and the normal `terminal` marker. The selection report distinguishes `display_frames_inspected` from `frames_retained: 1`, and retains `range_publication_complete: false`. Terminal `frames_decoded` counts every inspected native display output. Retained counts include reuse, not just newly allocated disk objects.

A storage or output interruption after publication begins can still leave committed or resumable custody. Keep the deployment and any emitted frame root; repeat the exact approved publication. Retry revalidates retained source and refuses damaged completed pixels rather than repairing them. There is no atomic transaction spanning codec work, storage, authority and stdout.

Omitting `--output-index` preserves the pre-selection all-frame approval encoding, preview fields, frame identities and incremental-prefix behavior, including main's effective native budget binding. Read and verify do not accept `--output-index`: the exact root already selects their retained frame.

## Reproducible focused checks

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-video
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test video_selection_cli
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test video_publication_cli
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test video_publication_contract
```

Unit contracts cover approval isolation/compatibility, full-range drain, late refusal, omitted outputs, bounds and selection ownership. Linux native-process contracts cover both codecs, cold read/replay, exact retries, single-root retention, display reordering, precise budget boundaries, corrupt retained pixels and rejection by replay of a self-consistent wrong-pixel fixture. Test subprocesses have explicit output/lifetime limits and are reaped.

These reference checks do not qualify cameras, detector accuracy, physical continuity, absence, or a release. No camera access, identification, alert or other external-effect authority is added.
