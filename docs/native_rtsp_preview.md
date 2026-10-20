# Native RTSP live preview

`fss-capture-rtsp` can show its current AVC or HEVC recording in a local browser
while capture continues. Preview serves the actual native fragmented MP4 remux
after the matching original recording window becomes locally durable. It is
optional, explicitly **unredacted**, and limited to the capture's Linux host at
`127.0.0.1`.

## Enable it on an existing capture command

Start with your complete, device-specific command from the
[native capture guide](rtsp_capture_cli.md). Remove its previous `--approve`
value and append these arguments:

```text
--preview-port 0 --allow-local-unredacted-preview yes
```

Run that complete command to obtain a new JSON plan. Check `live_preview`, the
`bounds.preview_*` values, and the returned approval. Repeat the same arguments
with that approval to execute. Planning does not bind a listener, read a secret,
or start camera input. Preview permission and every effective bound change the
approval; an earlier capture-only approval does not authorize preview. For
`retain-source` or `reconnect`, use the enclosing command's returned approval.

Port `0` requests an available local port. An approved running capture prints a
private viewer link to **stderr**. Open that exact link in a browser on the
capture host. The normal stdout JSONL transcript contains preview accounting,
not the link's secret. Omitting all preview arguments leaves preview disabled.

### Allow time for real recording windows

Choose the existing `--stop-after-pictures`, timeout, and recording limits so
the camera can produce multiple natural IDR-led windows while capture remains
active. An IDR is an independently decodable keyframe. Preview waits for a real
window boundary and durable source publication; it does not request or invent
keyframes. `--max-window-pictures` limits a window's size and does not force a
new keyframe or a shorter GOP.

The final explicitly sealed window is published during capture drain. **Preview
closes before drain and does not serve that final window.** A capture containing
only its final window can remain at “Waiting for a durable recording window”
until it closes. Preview delay therefore follows the source's window closure,
publication progress, and browser polling, rather than a promised frame latency.

## Limits

All numeric arguments are unsigned decimal integers. These are the CLI defaults
and accepted ranges; the fragment bound must also fit inside the ring bound.

| Argument | Default | Accepted range / meaning |
| --- | ---: | --- |
| `--preview-port` | Disabled when absent | `0..65535`; `0` selects an available loopback port |
| `--allow-local-unredacted-preview` | Absent | Must be `yes` when preview is enabled |
| `--preview-max-clients` | `4` | `1..16` simultaneous HTTP connections |
| `--preview-max-bytes` | `16777216` (16 MiB) | `65536..67108864`; published initialization and media bytes in the ring |
| `--preview-max-fragment-bytes` | `4194304` (4 MiB) | `1024..8388608`; initialization plus media for one window |
| `--preview-max-output-bytes` | `134217728` (128 MiB) | `65536..1073741824`; total HTTP output across the attempt |
| `--preview-max-age-ms` | `30000` | `100..60000`; age since staging, including publication delay |

Additional fixed limits apply:

- The ring retains at most eight windows. One unpublished candidate may occupy
  up to the fragment bound in addition to the ring. Initialization is limited to
  the smaller of 256 KiB and the fragment bound.
- An attempt accepts at most **256 HTTP connections across all viewers**. Page
  assets, manifest polling, media requests, and refused requests consume this
  allowance. Each response closes its connection. Polling can exhaust it before
  the capture deadline even when little media has been sent; refreshing does
  not reset it.
- Each accepted connection has a **five-second request-and-response lease**,
  shortened by the capture deadline. A media subscription also has a payload
  allowance of the smaller of 64 MiB and the configured total output bound.
- Requests are limited to 8 KiB and 64 headers. The capture owner performs
  bounded nonblocking socket work between native capture steps.

An oversized or expired preview derivative can be omitted while its original
recording proceeds. A slow or partially delivered response is disconnected
when its window is evicted; bytes from another window are never substituted.
The browser reports skipped sequences and windows unavailable before delivery.
Those counts describe **preview omissions**, not an assessment of recording
loss or scene coverage.

Preview startup or delivery failure does not by itself fail an otherwise valid
recording. The terminal `live_preview` report includes connection counts,
published/skipped/evicted windows, byte accounting, and `last_refusal`.
Capture authority, deadlines, cancellation, and recording failures still apply.
The listener and preview memory close when the attempt ends or enters drain.

## Privacy and local access

The viewer shows the source without masking or redaction. Enabling it requires
the explicit local disclosure flag as well as the capture approval. The session
binds the selected sensor, stream, generation, source anchor, receive/decode
clocks, and disclosure approval. A different source or initialization requires
a new session.

Linux entropy supplies a fresh 128-bit viewer secret. It is separate from camera
authentication and gives no camera-control or source-publication authority. The
link carries its 32 hexadecimal characters after `#`. The page removes that
fragment from the address bar and sends the secret in `X-FSS-Preview` on API
requests. Keep the original link private; opening it without the fragment does
not authenticate a viewer. Reloading the cleaned URL requires reopening the
original link while the same attempt is still active.

The gateway requires the exact `127.0.0.1:PORT` host and rejects cross-origin
requests. Its responses use `Cache-Control: no-store`. It does not provide
remote access, TLS, proxy configuration, or vendor credentials to the browser.

## Browser and HTTP behavior

The supplied page uses Media Source Extensions and checks the exact codec MIME
description from the native initialization. AVC is signalled as `avc1`; HEVC as
`hev1`. Playback requires the browser to support that particular configuration.
Unsupported codec support is reported in the page; there is no transcoding or
automatic codec fallback. Browser playback does not certify camera coverage or
change the original recording's custody status.

The same-origin reader uses these endpoints:

| Endpoint | Response |
| --- | --- |
| `GET /api/manifest` | `fss.live-preview.v1` metadata for the latest available durable window, its recording root, codec, media ticks, lengths/digests, and bounded status |
| `GET /api/window/SEQUENCE` | The exact selected resident window: MP4 initialization followed by its media fragment, with `X-FSS-Recording-Root` and `X-FSS-Window-Sequence` response headers |

Both require `X-FSS-Read: 1` and `X-FSS-Preview: TOKEN`. The secret is not accepted
as a query parameter. A missing or evicted window returns `404`; current access
or capacity refusal can return `403`, `410`, or `429`. The client accepts only a
complete response matching the manifest's length and original recording root.
Media timestamps describe the explicit decode clock; capture time remains
unknown.

This implements the bounded local portion of **FSS-057**. Masked preview, remote
WebRTC delivery, coordinated multi-camera viewing, and full browser/deployment
qualification remain outside this implementation's claim.

Implementation references:
[CLI bounds](../crates/fss-cli/src/bin/fss-capture-rtsp/preview_plan.rs),
[local gateway](../crates/fss-cli/src/bin/fss-capture-rtsp/preview.rs),
[browser reader](../crates/fss-cli/src/bin/fss-capture-rtsp/preview/preview.js), and
[native preview contract tests](../crates/fss-reference/tests/native_preview_contract.rs).
