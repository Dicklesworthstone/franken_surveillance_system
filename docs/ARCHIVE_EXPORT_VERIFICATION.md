# Verify an independently copied recording export

`fss-archive verify-export` checks an existing `fss-archive export` bundle using only
the copied files. The original archive may be offline, deleted, or on another host.
The command opens no deployment, archive writer, privacy owner, or network connection,
and creates, repairs, deletes, and replaces no files.

To turn a successfully verified selection into a new queryable native archive,
use [the separate `restore-export` operation](ARCHIVE_EXPORT_RESTORATION.md).
It requires a fresh destination and current privacy authority, preserves the
original recording bytes, and constructs new catalog pages for the selection.

Supply the SHA-256 of the exact original `COMPLETE.json` bytes through an independently
retained trusted channel. A digest calculated only from an untrusted copy does not
authenticate its origin. Also supply the intended codec and complete recording/clock
scope; the bundle cannot choose its verifier or replace those arguments.

```sh
fss-archive verify-export \
  --root "$EXPORT_BUNDLE" \
  --expected-completion "$EXPORT_COMPLETION_DIGEST" \
  --codec hevc \
  --sensor sensor-front --stream stream-front --generation 7 \
  --anchor "$RECORDING_ANCHOR" \
  --receive-clock "$RECEIVE_CLOCK" \
  --decode-clock "$DECODE_CLOCK" --time-scale 90000 \
  --max-windows 64 --max-objects 387 \
  --max-total-bytes 536870912 \
  --max-read-bytes 1074003968 --max-io-calls 100000 \
  --timeout-ms 30000
```

The variables above are caller-supplied paths and `sha256:` identities. Use the scope
retained with the export. `avc` and `hevc` are the only codec choices; there is no
metadata-controlled codec fallback. The operation currently requires Linux with
`/proc/self/fd` available. Other hosts return `UnsupportedPlatform` before file reads.

## What is verified

The command first rehashes `COMPLETE.json` against the supplied pin. It strictly parses
the versioned completion format, refusing duplicate keys, unknown fields, unsupported
schemas, malformed numbers, changed scope, and inconsistent accounting. A dedicated
4 MiB parser profile accepts the exporter's complete advertised report size without
increasing ordinary control-input limits.

For every selected whole window, it checks the six exact generated filenames and their
declared lengths and SHA-256 identities:

| File suffix | Verification |
|---|---|
| `source.bin` | Original retained packet bytes and native source-provenance verification |
| `init.mp4` | Exact initialization object and its native recording relationship |
| `media.m4s` | Exact media object and native source-to-media reconstruction |
| `index.bin` | Exact index, caller scope, native timing, and source mapping |
| `root.bin` | Exact canonical `ObjectManifest`, root identity, and child closure |
| `playback.mp4` | Exact byte-for-byte concatenation of that window's initialization and media |

The adapter invokes the existing first-party `verify_recording` or
`verify_hevc_recording` implementation with the caller's `RecordingScope`. It also
compares the native summary's root, scope, time scale, and decode interval with the
pinned report. Rehashing alone cannot turn a relabeled AVC object into a valid HEVC
recording.

The directory must contain precisely those files, `REQUEST.json`, and `COMPLETE.json`.
The exporter's optional `COMPLETE.json.pending` is allowed only when its bytes exactly
equal the pinned completion; transported copies need not retain the original hard-link
relationship. A pending file without `COMPLETE.json` remains incomplete. Extra names,
directories, symlinks, missing objects, duplicate roots, and substituted paths refuse.

New exports use `fss.local_archive_export_completion.v2`. Its required `request_sha256`
field pins the exact original `REQUEST.json` bytes, including its byte reservation.
A mismatched digest refuses the copy before the verifier opens any recording payload.
The verifier also checks the request semantics and reports `sha256_pinned_by_completion_v2`.

The legacy v1 completion does **not** bind the exact bytes or reservation in `REQUEST.json`.
The verifier checks that request's schema, snapshot, codec, query, whole-window flag,
completion filename, and bounded reservation are consistent. The result separately
reports `request_sha256_observed` and labels it
`semantic_consistency_only_unpinned_by_completion_v1`. This is a new observation of
ancillary request bytes, not recovered original authorization.

## Bounds and changes during a read

Every directory component is opened relative to the previously held directory
descriptor. Inventory and payload reads use the final held descriptor. Safe read-only
opens use the platform's `O_NOFOLLOW`, `O_NONBLOCK`, and directory flags. This prevents
ancestor replacement from redirecting payload reads and avoids blocking on a special
file substituted during an open. Named identities, open-handle identities, file sizes,
types, and modification/change stamps are compared at read boundaries.

One request allowance covers directory traversal, inventory, initial reads, and final
verification. Every file is read again before completion, followed by another closed
inventory check. Read reservations include the bounded EOF probe and remain charged
after failure. Limits never refill between windows or verification passes.

| Option or fixed bound | Default | Maximum |
|---|---:|---:|
| `--max-windows` | 4,096 | 4,096 |
| `--max-objects` (copied filenames) | 24,579 | 24,579 |
| `--max-total-bytes` (sum over copied filenames) | 1 GiB | 1 TiB |
| `--max-read-bytes` (both passes and EOF probes) | 4 GiB | 1 TiB |
| `--max-io-calls` | 1,000,000 | 4,000,000 |
| `--timeout-ms` | 30,000 | 3,600,000 |
| Complete report | 4 MiB | 4 MiB |
| Request file | 4 KiB | 4 KiB |
| One complete native recording | 32 MiB | 32 MiB |

Counting both completion filenames is conservative even when they share an inode.
Cancellation and deadline checks run at bounded I/O steps and between native recording
verifications. One bounded native verification is not a preemptible filesystem or codec
operation. A changing file or namespace causes refusal when observed; the command does
not claim an atomic immutable filesystem snapshot or future availability.

## Result and limits of the claim

Successful output uses `fss.local_archive_export_verification.v1` and includes the
completion identity, exact supplied scope, verified window/file/byte counts, cumulative
read and I/O costs, ancillary request observation, and explicit claim boundaries:

- `native_source_provenance_verified: true` covers the selected copied recording objects.
- `playback_bytes_verified: true` means exact initialization-plus-media bytes.
- `decoded_pictures_verified: false` preserves the distinction from pixel decoding or a
  playback-device compatibility test.
- `original_catalog_reconstructed: false` means the original archive snapshot, omitted
  windows, and selection completeness have not been independently recovered.
- `current_archive_or_disclosure_authorized: false` grants no live retention, privacy,
  export, or source-access authority.
- `coverage_claim: "not_claimed"` preserves unknown coverage and physical absence.

A legitimate export selecting zero windows verifies with `verified_windows: 0` and
zero recording bytes. Its pinned query/gap metadata remains metadata; it establishes
neither footage nor physical absence.

Refusals retain distinct incomplete-publication, completion-pin, scope, report-format,
inventory, missing-file, unsafe-path, integrity, changed-state, quota, cancellation,
deadline, platform, and host-I/O outcomes. There is no partial success report or automatic
repair/resume. Ordinary `inspect`, `query`, `verify`, `export`, and `query-utc` retain
their existing source-archive recovery and locking behavior.

## Regression coverage

The production bundle-reader suite exercises copied files, independent pending copies,
pin/scope/codec mismatch, closed report and directory inventory, source corruption,
hash-consistent invalid playback, request semantics, reports larger than 2 MiB,
cumulative budgets, cancellation/deadline, directory replacement, and exact empty/gapped
selection accounting. The full CLI suite additionally uses real AVC and HEVC exports,
copies them, removes the original archives, and invokes the new operator entry path;
it also rejects a hash-consistent bundle retagged to the wrong native codec.

The focused full-composition command is:

```sh
cargo test -p fss-cli --lib archive_cmd::verify_export
```

These regressions do not qualify remote replication, cryptographic provenance of an
unpinned report, current disclosure policy, pixel decoding, or the native release matrix.
