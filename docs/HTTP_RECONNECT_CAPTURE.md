# Native HTTP capture across connection loss

`fss-capture-reconnect` connects the existing `HttpReconnectRecording` owner to an
operator-driven executable. It records original HTTP reads durably before parsing them, verifies
complete JPEG source mappings, and crosses to the next connection only after verifying and
reporting the preceding generation's complete retained prefix. It is separate from `fss-capture`:
that command's single-connection behavior, approvals and output remain unchanged.

## Preview and approval

```sh
fss-capture-reconnect \
  --root /absolute/path/to/camera-archive \
  --peer 192.168.1.20:8080 --host camera.local --target /video \
  --source sha256:SOURCE --generations 40,41,50 \
  --receive-clock sha256:CLOCK --retention-evidence sha256:RETENTION \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --initial-backoff-ms 250 --maximum-backoff-ms 5000
```

Replace the digest placeholders with nonzero owner-selected SHA-256 identities. Preview does not
read a clock, create a directory or connect. Review the complete plan, then repeat the same
arguments with `--approve sha256:APPROVAL` from that preview. The approval covers the exact route,
root, principal, generations, receive/retention scopes, every effective limit (including native
parser defaults), stop rule, backoff and completion policy. It is not camera authentication.

No generation is inferred, incremented or reused. One through 32 strictly increasing generations
are required. A source namespace containing prior reads is a recovery task, not permission to
restart that generation. There is no automatic crash resume, daemon or implicit retry of a failed
command. Preserve stdout independently; `fss-archive check-http` can inspect each exact prefix
using its source, generation, receive clock, retention evidence, scope, head, read and byte counts.

Only a literal-IP, credential-free, explicitly approved plaintext endpoint is admitted. DNS,
credentials, redirects and endpoint changes are refused. Raw response headers and encoded media
are retained locally and **not encrypted** by this command. No source bytes or pixels are printed.

## Progress and termination

JSONL uses `fss.http_reconnect_capture.v1`. `wire_prepared` precedes storage; `wire_durable` reports
durable source independently of the later parser acknowledgement. `frame_verified` means original
source mapping was reverified, not that the JPEG was decoded or an event observed.

`boundary_verified` contains the source generation, complete prefix, original native completion or
failure, next reserved generation, backoff and stop reason. It is flushed before releasing the
recorder's barrier. The recorder re-verifies the prefix again before release. A broken output sink,
missing source root or storage refusal prevents the next connection. Flushing stdout means the
writer accepted the row; it is not proof that an external consumer durably checkpointed it.

The existing supervisor, not the CLI, decides which failures can retry: selected native transport
failures and explicit HTTP/MIME truncation. HTTP statuses (including 503), malformed framing,
authority/cancellation failures and exhausted resource limits are terminal. `--after-complete yes`
explicitly permits a fresh generation after genuine HTTP/MIME completion; the default is `no`.

`--stop-after-frames N` is an intentional whole-run stop ceiling, not EOF. Natural completion may
end the run sooner. A successful final response after an earlier recoverable failure does not erase
that failure: both boundaries remain in the finish record. Exhausting slots on a failed response
returns nonzero. Completing the final explicitly reserved response returns success. Counts never
certify continuous physical coverage or an empty scene.

The finish record preserves each generation's last durable pin, whether each boundary was released,
pending publication, aggregate network/work counts and any accepted bytes not published before
failure. On cancellation/deadline/output refusal the socket is retired without new network work;
only durable prefixes survive process exit. No unapproved rescue I/O or deletion occurs.

## Limits and non-claims

Per-slot read/byte/frame/I/O reservations are checked in aggregate before I/O: at most 8,192 reads
and 512 MiB original bytes over the entire plan. Unused slots' allowances are never lent to another
slot. Source/framing work, poll count, report bytes and one absolute deadline span all connections.
There is one extra native lookahead part per slot to recognize EOF after exactly the admitted frame
count; it is never transferred if it exceeds the frame allowance. Count limits are not clean EOF.
Generation identities are decimal strings in output, preserving all 64 bits.

No event, alert, coverage witness, calibrated capture time, physical-camera identity
or durable completion root is created. Pixel decoding is disabled unless explicitly requested below. The existing recorder owns raw source durability; the CLI
adds no new ledger, journal, effect protocol or universal agent operation.

## Optional native decoding under current privacy policy

Add these options to the preview and exact approved rerun:

```sh
  --decode grayscale \
  --privacy-root /absolute/path/to/existing-deployment \
  --site site:home --sensor sensor:front \
  --max-decode-work 1000000000 --max-dimension 4096 --max-pixels 4194304
```

`grayscale` and `ycbcr` are explicit JPEG component interpretations, not guesses. Both return
luma diagnostics; the YCbCr path also validates chroma entropy but does not claim RGB output.
The existing native decoder validates the entire frame. Its identity and every byte, dimension,
pixel, marker and work limit are bound into the version-2 acquisition approval. Raw-mode approval
bytes and reports are unchanged; a raw approval cannot authorize decoding.

A single decode budget is created for the complete run, never per frame, retry, or connection.
A second connection cannot revive an exhausted budget. The named privacy deployment must already
exist and its current sensor mask must resolve before any TCP or archive open. It is not silently
created, and it must be separate from the archive. Each frame resolves the existing retained mask,
applies it before exposing pixel digests, rechecks the binding and generation before returning,
and checks separate decode authority before and after the work. Missing policy custody, mismatched
resolution, stale authority and decode errors stop the run without reconnect or unmasked fallback.

`frame_verified.pixel_decode` then contains dimensions, the **masked** luma digest and the exact
policy digest/generation (or explicit no-policy marker). No pixels or raw response headers are
printed. Original encoded source remains private, unmasked local custody, as in the original
capture command. Masking a derived plane does not encrypt or delete that original.

The finish record distinguishes originals transferred from successful decodes and reports shared
decode work used/remaining and reconstructed pixels. If a decode fails after the original frame
was verified and released by the recorder, its generation/ordinal/encoded digest remain in
`native_decode.pending_frame`, backed by the reported durable original prefix. There is no
claim of a durable decoded object, automatic recovery, or physical absence.

## Validation boundary

Native regressions in the binary cover exact approvals, malformed plans, aggregate ceilings,
integer extremes, real loopback truncation followed by a fresh generation, complete-response
policy, terminal HTTP errors, occupied namespaces and failure of the boundary output sink.
Additional native tests cover multi-connection masked decoding, exact shared decode-budget
exhaustion, missing privacy custody before TCP, mask updates between frames, resolution refusal,
and authority withdrawal after native work without emitting a result.

```sh
cargo test -p fss-cli --bin fss-capture-reconnect --locked --offline
```

Native compilation, tests, rustfmt, Clippy and local qualification were not run in the implementation
environment because no Rust toolchain was available. Any independent Python checks are design and
source-audit evidence only, not execution of Rust. No real-camera or production qualification claim
is made and no bead is closed by this CLI integration.
