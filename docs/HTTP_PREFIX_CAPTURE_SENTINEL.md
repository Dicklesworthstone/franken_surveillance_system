# Bounded native detection from a continuous HTTP camera

`fss-capture-reconnect sentinel-prefix` acquires an explicitly approved number of complete
JPEG parts from one HTTP MJPEG generation, closes the socket, and feeds that exact source-frame
range to the native trained detector. The camera can keep its response open indefinitely;
successful acquisition does not depend on peer EOF, Content-Length completion or a final MIME
delimiter. The command retains an original prefix and never manufactures an ended history.

Use [`sentinel`](HTTP_CAPTURE_SENTINEL.md) when you want native reconnect processing across
ended responses. Use `sentinel-prefix` for a requested frame-count stop on one ongoing response.
The separate commands have separate approval domains and operator formats.

## Preview, then approve a bounded capture

The ordinary capture route, source custody, plaintext and owner acknowledgements still apply.
Exactly one generation and one explicit camera/time binding are required. The following example
uses an example address and shell variables for the actual source, receive-clock,
retention-evidence and local-package digests:

```sh
fss-capture-reconnect sentinel-prefix \
  --root /srv/fss/live-prefix-001 --peer 192.0.2.10:80 \
  --host camera.example --target /mjpeg \
  --source "$SOURCE_DIGEST" --generations 10 \
  --receive-clock "$RECEIVE_CLOCK_DIGEST" \
  --retention-evidence "$RETENTION_EVIDENCE_DIGEST" \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --durable-history yes --recoverable yes \
  --stop-after-frames 32 --max-frames 64 \
  --deployment-root /srv/fss/deployment --site site:property \
  --binding 10,sensor:front,stream:front,180000000000,100000000000,1000000,25 \
  --interpretation ycbcr \
  --package /srv/fss/detector.fmpk --package-digest "$PACKAGE_DIGEST" \
  --read-originals yes --read-model yes --execute-perception yes \
  --retain-analysis yes \
  --sentinel-every-frames 8 --sentinel-burst-frames 2 \
  --sentinel-max-inferences 8
```

Replace the route and time assumptions with the authorized camera's intended recording
coordinates. The preview performs no filesystem, clock, model or network I/O. Repeat the exact
command with `--approve` set to its outer `approval_digest`. The native capture approval and
the ended-response command's approval cannot authorize this selection.

Approved execution validates separate paths, the exact local package, backend and selected
detection contract before contacting the camera. It checks path admission again after model
compilation. An existing archive refuses before contact, including after a successful prior
run. No credentials, DNS, redirects, fallback route, automatic reacquisition or model download
is added.

`--durable-history yes` retains the ordinary capture owner's history capability. A successful
count stop has no ended history to publish. Native capture rows continue to expose original
prefix and recovery pins; an actual early source failure may also retain a failed ended
boundary. Neither case authorizes replacement footage or a success claim when the count was
not reached.

## Keep the frame counts separate

| Count | What it bounds or measures |
| --- | --- |
| `--stop-after-frames N` | Exact number of complete MIME-framed JPEGs acknowledged before closing the camera connection. |
| Capture `--max-frames` | Per-generation delivery ceiling, which must cover N. |
| Analysis `--max-frames-per-generation` | All complete originals discoverable in the received prefix, including read-ahead. Default 4096, maximum 4096. |
| `acknowledged_frames` | First N source frames admitted to the native sampling schedule. |
| `imported_read_ahead_frames` | Additional complete received JPEGs retained for custody but outside this analysis selection. |
| `resource_usage.inferences` | Model calls actually executed within the selected first N frames. |

A network read can contain more JPEGs than the delivered count. The native importer preserves
every received byte, including headers, wrappers, read-ahead JPEGs and a partial tail, then
selects every complete original JPEG within the separately approved import ceiling. Exceeding
that ceiling refuses; it never truncates retained originals to make the operation fit.
Perception samples only segments `0..N`. Read-ahead remains unobserved by this run.

Whole bursts use the existing long-sentinel schedule, at most 64 model calls. Source, pixel,
JPEG and detection-head allowances are shared across the selected bursts. The prefix preview
reports the exact first-N reservation rather than a hypothetical schedule over all possible
read-ahead. Current destination privacy applies before inference and is rechecked before the
final report. Original bytes, all imported source capsules and the complete destination source
closure are also revalidated, including the unsampled tail.

`source_ending` is the native importer's observation: an ongoing response is `pinned_prefix`.
If bytes already received independently prove both HTTP and MIME framing completion, the
importer may report `explicit_framing_complete`. Neither result invents peer EOF, an ended
acquisition history or scene coverage.

## Recovery without another camera capture

Save complete JSONL independently. Parent rows use `fss.http_prefix_capture_sentinel.v1`;
ordinary capture rows retain their existing format.

| Parent row | Recovery information |
| --- | --- |
| `capture_ready` | Exact model and contract validated before camera contact. |
| `prefix_ready` | Exact successful count-stop prefix, selected count, native plan digest and approved `offline_import_argv`. |
| `imported` | Durable import identity/root, native ending, read-ahead accounting and `offline_analysis_argv`, emitted **before inference**. |
| `completed` | Native long-sentinel report, retained report/root and `native_sentinel_replay_argv`. |
| `capture_incomplete` | The requested count or exact settled prefix contract was not satisfied. No automatic analysis begins. |
| `analysis_failed` | Original import continuation and, once acknowledged, analysis continuation remain available. Earlier writes may be durable. |

Each continuation is a literal argv array, including the program name; paths containing spaces
remain one argument. Import uses the existing `fss-import-http` parser and exact approval
encoder. Analysis uses `fss-infer package-detect` with the exact import, first segment, N,
package, backend, threshold, sampling and native resource settings. Both fresh analysis and
retained replay carry the selected model-output ceiling through `--max-output-bytes`.

If the import progress sink fails, native processing stops before the first model call. The
verified import remains durable. An explicit cold import retry can recover its identity and
then continue analysis without contacting the camera. The command never starts a second
capture to repair a lost response or failed analysis.

An offline continuation is a **new explicit bounded invocation** of the existing native owner.
It preserves source and computation identity, rather than resuming the live process's remaining
work or time account. In particular, the ordinary HTTP importer retains its own bounded reader;
it has no copy of the live wrapper's `--archive-read-bytes` meter. Review the chosen operation's
bounds before invoking it. The live process itself never refills its accounts between model
preflight, capture, import and analysis.

Retained `fss-infer sentinel-replay` works from verified destination custody after the loose
capture archive and package go offline. It reproduces the exact stored native computation;
no effect, event, learning activation or camera authority travels with the replay command.

The open-socket loopback tests verify bounded stopping, source preservation, failure and cold
continuation. They do not qualify physical-camera interoperability, calibrated detector quality,
absence claims or continuous scene coverage.
