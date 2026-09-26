# Native HTTP camera capture from the operator CLI

Status: implemented reference behavior, not production-qualified. `fss-capture http` connects
one explicitly authorized, credential-free HTTP MJPEG endpoint to the existing durable
`HttpRecording` owner. It adds no network stack, MIME parser, media codec or archive format.
It does not run a detector, create an event, or send an alert.

## Preview and approve one bounded recording

Use a literal IP/port for `--peer`; `--host` is the exact owner-approved HTTP Host header,
not a DNS lookup. Targets are absolute non-secret paths. The native route validator rejects
credentials, query strings, percent escapes, fragments, redirects and ambiguous routes.
The archive root must be an absolute, non-root path. Do not use a deployment/other service's
root as the archive root. The source, generation, receive-clock and original-retention
identities must be independently selected and retained by the operator.

```sh
capture_args=(
  http --root "$ARCHIVE_ROOT" --peer "$CAMERA_IP_PORT"
  --host "$CAMERA_HOST" --target /video
  --source "$SOURCE_DIGEST" --generation 1
  --receive-clock "$RECEIVE_CLOCK_DIGEST"
  --retention-evidence "$RETENTION_DECISION_DIGEST"
  --owner-authorized yes --plaintext yes --retain-originals yes
  --timeout-ms 30000 --max-frames 128 --stop-after-frames 30
)
fss-capture "${capture_args[@]}"
```

This prints a plan without opening an archive, privacy deployment or camera. Review its
route, destination, principal, scope, stop condition and limits. Repeat with its exact
`approval_digest`:

```sh
fss-capture "${capture_args[@]}" --approve "$APPROVAL" > "$TRANSCRIPT_JSONL"
```

The approval is for this bounded acquisition, not proof of the unknown future bytes, a
sensor identity, a detected event or an external effect. Changing a bound, route, root,
principal, source or privacy selection requires a new preview. An incorrect approval fails
before opening storage or attempting TCP. `--principal` is an attribution label for the
invoking owner-authorized local process, not remote authentication or privilege escalation.

There is exactly one TCP connection attempt. No hostname resolution, credentials,
authentication retry, redirect following, reconnect loop, worker or model download exists in
this command. Select an endpoint whose original response headers can legitimately be retained;
raw headers may contain sensitive information. The explicit retention identity is not an
expiry schedule. Original headers and JPEGs are unencrypted local custody, never printed to
stdout and never presented as privacy-redacted exports.

## Bounded request versus complete source

`--stop-after-frames N` requests up to N complete, custody-verified MIME parts. Reaching N
returns `requested_count_reached`, `request_satisfied: true`, and **`stream_complete: false`**.
No completion root is invented. This is useful with an indefinitely streaming camera.
A socket read may contain lookahead bytes beyond the last selected part; those already
accepted original bytes remain in the reported prefix and are not relabelled as parsed frames.

Without the deliberate stop, native HTTP and MIME must both finish before a completion root
can be prepared and published. Fixed-length and chunked bodies use native framing termination;
a close-delimited response needs an actual peer EOF. Only successful native completion
publication produces `native_complete` and `stream_complete: true`.

Timeout, malformed framing, failed decode, budget exhaustion, storage failure and output
failure are refusals, not successful count stops, EOF, empty scenes or evidence of absence.
A hard `--max-frames` limit is distinct from `--stop-after-frames`. A refused capture exits
nonzero even when earlier complete frames and original reads were retained successfully.
A natural source end before the requested count is a valid native-complete bounded capture.

## Optional full JPEG validation with retained privacy policy

Default `--decode none` verifies original bytes, HTTP/MIME framing and source mapping only.
It makes no pixel-decode claim. To validate every transferred JPEG with the existing native
codec and the sensor's current retained mask, add:

```sh
--decode grayscale --privacy-root "$PRIVACY_DEPLOYMENT" --site "$SITE" --sensor "$SENSOR"
```

Use `ycbcr` for explicit Y/Cb/Cr interpretation. Decoding requires all three privacy options;
partial or inapplicable privacy arguments fail before execution. The privacy deployment must
already exist and must not overlap the archive root. An absent/damaged policy store is not
created as a replacement empty policy store. The named sensor is an owner assertion, not
camera authentication. A valid sensor with no retained mask reports `explicit_no_policy`.

The current policy is resolved by `SensorMask` before native decoded luma reaches its digest.
Rows contain dimensions, masked-luma digest, applied policy digest/generation or the explicit
no-policy marker. No pixels are emitted. Wrong stream resolution or damaged policy custody
refuses the decode; original custody remains distinct from pixel derivation. The CLI holds
the existing deployment's exclusive writer lock while reading its policy, so concurrent mask
updates require that owner to release the deployment first. No policy is changed by capture.

Decode selection and the exact privacy root/site/sensor bind a version-2 acquisition approval.
Framing-only plans retain their version-1 approval bytes, including explicit `--decode none`.
Both modes keep the original native archive formats unchanged. Changing policy between
preview and execution applies the current retained binding, not an unretained caller mask.
The approval explicitly selects that current-policy behavior rather than a fixed old policy.

## Recovery transcript and cold checking

Preserve complete stdout JSONL rows independently of the archive. A `wire_prepared` row names
the exact expected prefix **before** its root-last publication. A `wire_durable` row confirms
the native publisher returned success; `parser_acknowledged` is separate, so late camera
revocation cannot hide successful disk custody. A `completion_prepared` row likewise precedes
terminal publication. Prepared pins alone are never proof that a write happened.

The terminal row names the last confirmed original prefix, any pending wire/completion key,
actual receive/parse/transfer counts, consumed native work, and any typed refusal. Output
capacity reserves space for this terminal row, but a broken output sink can prevent even it
from being delivered. Writer acceptance/flush is not a filesystem or remote acknowledgement;
stdout may block and cannot be preempted by the cooperative capture deadline. Archive-open
locking, verification, recovery sync and layout initialization retain their existing semantics.
This is not a forensic read-only open or a hard real-time filesystem guarantee.

On refusal, accepted but unpublished raw input is reported separately. In-memory uncommitted
input is lost when the process exits. Staged or visible-but-unconfirmed objects may remain;
they are not claimed durable. The command does not repair, erase or reconnect to replace them.
Use an independently saved exact pin and the existing checker:

```sh
fss-archive check-http --root "$ARCHIVE_ROOT" \
  --source "$SOURCE_DIGEST" --generation 1 \
  --receive-clock "$RECEIVE_CLOCK_DIGEST" --retention-evidence "$RETENTION_DECISION_DIGEST" \
  --head "$PIN_HEAD" --reads "$PIN_READS" --bytes "$PIN_BYTES" \
  --read-originals yes --decode none
```

Add `--completion-root "$COMPLETION_ROOT"` only for an independently retained terminal key.
For a pixel check, use the same explicit decode/privacy options. A partial prefix may produce
a nonzero `prefix_exhausted`/refused report; this does not erase already verified frame rows.
Retrying capture against an occupied exact source namespace is refused before connecting.
Start a deliberately new source scope for a new acquisition; never interpret this as recovery
of the old wire or physical camera exposure.

## Bounds and verification

The command has whole-session source, framing, decode, syscall, poll, frame, read, byte and
transcript bounds. Native budgets never refill per frame. Defaults and selected limits are
shown in the preview; use `fss-capture --help` for options. Native storage is limited to 8,192
roots, 65,536 spool objects and 1 GiB total spool payloads. This quota covers the shared archive
root, not a promise of free space or a retention schedule. The network lease is measured by a
local monotonic owner clock and is not a source capture timestamp or clock-alignment proof.

```sh
cargo test -p fss-cli --bin fss-capture
cargo test -p fss-cli --test http_capture_cli_contract
```

The tests include seven base CLI contracts, three decode-scope contracts, and one native
integration harness with 12 loopback scenarios: preview/stale/route refusal, three framing
modes with cold verification, occupied-namespace refusal, count stop, hard frame limit,
timeout, malformed framing, full-mask native decode/cold equivalence, decode-budget failure,
missing privacy authority and corrupt original storage. Some checks share a scenario.
Python supplies only the fixture-owned socket and assertions; all FSS semantics run in the
Rust binaries. Python fixture syntax and Rust lexical/structural checks ran in the authoring
environment. The Rust test command was attempted but cargo was unavailable; compilation,
native tests, rustfmt and Clippy are **not verified**. No qualification claim is promoted.
