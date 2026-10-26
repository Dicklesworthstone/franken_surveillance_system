# Owner-scoped ONVIF snapshot capture

The snapshot command negotiates one JPEG through an explicitly approved ONVIF Media1
service, then retains its exact bytes through the ordinary file-ingest custody path.
It uses the native ONVIF HTTP owner for all three requests: GetProfiles,
GetSnapshotUri, and the returned snapshot GET.

## Capture one snapshot

Use the literal camera address and its Media1 service path:

```sh
cargo run --locked -p fss-cli --bin fss-capture-onvif -- \
  --xaddr http://192.0.2.10:8080/onvif/media \
  --root /absolute/path/to/deployment \
  --sensor-id sensor:front-door \
  --stream-id stream:front-door-snapshot \
  --receive-time-ns 1793011200000000000 \
  --owner-authorized \
  --timeout-ms 30000 \
  --max-source-bytes 4194304
```

Replace the example address, root, identities, and receive timestamp with the values
for the device you own or are authorized to use. The receive timestamp describes
arrival; the command does not infer when the camera captured the image.

For a hostname URL, independently resolve and approve a literal peer, then supply it
with `--peer IP:PORT`. The hostname remains the exact HTTP Host authority.
The command never performs DNS, and a literal URL cannot be paired with a different
IP. An explicit URL port must match the pinned peer; an omitted URL port means 80.

`--profile TOKEN` selects that exact advertised video profile. Without it, the
first advertised profile containing a video configuration is selected. An absent or
audio-only explicit profile is refused.

## Scope and resource limits

`--owner-authorized` approves the named device and media and the explicit
plaintext HTTP limitation. The returned snapshot URI must have the same exact
HTTP authority, including port spelling, as the approved Media1 service. A returned
URI cannot change the pinned socket address. Redirects, URI userinfo, HTTPS, malformed
targets, and authentication challenges are refused. This snapshot lane does not
borrow credentials or automatically use another ONVIF authentication mechanism.

The network session has one absolute deadline, including negotiation, connection,
writes, reads, framing, and final source release. The default is 30 seconds and the
maximum is 60 seconds. Connect attempts are additionally capped at five seconds and
the remaining session time. Subsequent socket operations are nonblocking and the
owning runtime checks cancellation and authority around each operation and wait.

The default source ceiling is 4 MiB; `--max-source-bytes` accepts 1 through
67,108,864 bytes. SOAP keeps its separate existing limits. HTTP Content-Length,
chunked transfer, and close-delimited bodies use the shared bounded framing owner;
ambiguous framing, unsupported coding, excess bytes, and incomplete bodies fail.
The source must contain exactly one complete marker-framed JPEG with frame metadata,
without omitted bytes, a second frame, or a truncated end. This is not a claim that
the image has been decoded.

## Custody and output

After the network owner drains and finalizes, a separate bounded file-import owner
stages the JPEG in a freshly created directory. On Unix the directory is mode 0700
and the source file is mode 0600. Staging never reuses an existing file or directory,
and its owner removes only its own source and directory on completion or cancellation.

The command imports the source as one JPEG frame, reopens the retained manifest,
checks its byte count and SHA-256 against the fetched source, and verifies the
durable source objects before emitting success. Storage work has its own source and
operation bounds; `--timeout-ms` is the network lease, not a storage deadline.

The JSON schema remains `fss.onvif_capture_cli.v1`. It reports the source digest,
import identity and root, observed network work, and approved route digest.
Camera-returned snapshot paths and queries are redacted because either may contain a
bearer token. Device-declared expiry remains explicitly supplied metadata; it is not
a trusted capture clock. `media_continuity` remains `unverified`.
A successful capture does not establish Profile T conformance, device identity,
a decoded scene, or sustained media continuity.

## Validation

The library contract tests in
`crates/fss-reference/tests/onvif_snapshot_contract.rs` exercise real loopback
transport, exact Content-Length/chunked source preservation, cross-origin refusal,
source bounds and JPEG failures, cancellation, deadline, redirects, and authentication
refusal. HTTP unit tests keep snapshot GET routes separate from SOAP/signing and
retain the SOAP allocation ceilings.

The command tests in
`crates/fss-cli/src/bin/fss-capture-onvif/tests.rs` cover native capture through
durable retained-source verification, token redaction, destination approval, no
deployment on route refusal, private staging, cancellation cleanup, and digest mismatch.
