# Retained camera-file workflow

`fss-file` is an operator utility over the persistent reference deployment and the existing
ADP-FILE adapter. It imports JPEG/MJPEG or Annex-B H.264 source bytes, reopens the resulting
ledgered import without the original file, verifies retained custody, and extracts exact
source segments. It does not run a model, certify live coverage, or claim that H.264 was decoded.

## Import

```sh
cargo run -p fss-cli --bin fss-file -- import \
  --root ./camera-evidence --site site:home \
  --input ./recording.h264 --sensor sensor:driveway --stream stream:main \
  --receive-time-ns 1000000000 --manifest-out ./import.manifest
```

Use a receive timestamp appropriate to the deployment's declared timeline. The example is a
synthetic one-second reference timeline, not a real capture timestamp. Without a complete
`--capture-start-ns`, `--capture-uncertainty-ns`, `--assumed-fps` tuple, capture time remains
`unknown`. A supplied tuple is explicitly an `operator_assumption`, never hardware clock proof.
The import's output reports `absence_certifiable=false` in either case.

The command reports the actual retained manifest and completion anchor, rather than treating a
newly reconstructed retry receipt as stored truth. A successful import also performs a complete
source-byte verification. Save the printed `import_identity=sha256:...` for subsequent commands.

## Reopen, verify and extract

```sh
cargo run -p fss-cli --bin fss-file -- verify \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST

cargo run -p fss-cli --bin fss-file -- extract \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --output ./first-segment.h264
```

Replace the digest placeholder with the exact 64-character digest reported by import. No input
path is required for these operations. `inspect` performs metadata/authority validation without
reading every source chunk. `verify` checks the full source in recorded chunk order, including
repeated chunks. `extract` verifies touched chunks and the assembled segment checksum before
writing bytes. JPEG/MJPEG extraction produces the original encoded JPEG segment, not a decoded
image. Metadata can be exported by any command with `--manifest-out FILE`; it is the existing
`fss.file_import.manifest.v1` canonical binary, not a new JSON or agent-envelope dialect.

## Boundaries

The local operator process and filesystem permissions are the trust boundary. `--principal` is an
audit label, not remote authentication. The reference context grants filesystem operations only;
there is no network-camera discovery, model execution, alert dispatch, or automatic repair here.
Only a completed final authority batch matching the currently visible import root is recoverable.
Missing, inconsistent, tombstoned or incomplete publications fail closed; no root is silently
substituted. These commands do not truncate damaged history or change retention policy.

Limits default to 512 MiB per source, 16 MiB per chunk and 16 MiB per returned segment. Set
`--max-source-bytes`, `--chunk-bytes` and `--max-segment-bytes` explicitly to narrow or change
these ceilings. Chunk and segment ceilings cannot exceed 64 MiB. For reads, `--chunk-bytes`
is an admission ceiling, not a request to rechunk stored evidence. Metadata has a fixed 16 MiB
ceiling and bounded collections. Partitioned manifests are refused until part resolution exists.

Exports must be new files outside the deployment. Existing destinations and symlinks are not
overwritten. Unix exports are created with owner-only permissions. Successful writes are fsynced;
this utility does not claim atomic export publication or directory-fsync durability. An I/O error
may leave a partial export for operator inspection. An export or verification failure does not
roll back an already committed import. The command returns a nonzero exit status on that failure.

This adds a usable reference workflow, not production or release qualification. Pinned-nightly
Rust tests and repository qualification must run before promotion.
