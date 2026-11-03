# Capture an HTTP camera and retain native detector evidence

`fss-capture-reconnect sentinel` combines one approved native HTTP acquisition with the
existing motion-independent RGB detector and its retained replay owner. The operator supplies
the camera route, source identities, every reserved generation's sensor and time assumptions,
and the exact local native model package. The command carries the actual durable history pin
into analysis directly; it does not parse a transcript, spawn a second program, or select a
newest history root.

This mode requires the camera to end its HTTP responses. A successful reconnect sequence may
include earlier failed responses; their native outcomes and usable originals remain visible.
An unfinished current prefix never becomes an ended history. In particular,
`--stop-after-frames` is refused by this mode before any I/O.

## Preview and approve the complete operation

Choose separate absolute paths whose parents already exist. The archive path must be new.
The deployment can already exist, and the model must be a separately retained regular file.
Use your actual source, receive-clock, retention-evidence and package digests for the variables
below. `192.0.2.10` is an example address; substitute an owner-authorized literal-IP route.

```sh
fss-capture-reconnect sentinel \
  --root /srv/fss/capture-001 --peer 192.0.2.10:80 \
  --host camera.example --target /finite-mjpeg \
  --source "$SOURCE_DIGEST" --generations 10,11 \
  --receive-clock "$RECEIVE_CLOCK_DIGEST" \
  --retention-evidence "$RETENTION_EVIDENCE_DIGEST" \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --durable-history yes --recoverable yes \
  --deployment-root /srv/fss/deployment --site site:property \
  --binding 10,sensor:front,stream:front,180000000000,100000000000,1000000,25 \
  --binding 11,sensor:front,stream:front,180000000000,110000000000,1000000,25 \
  --interpretation ycbcr \
  --package /srv/fss/detector.fmpk --package-digest "$PACKAGE_DIGEST" \
  --read-originals yes --read-model yes --execute-perception yes \
  --retain-analysis yes \
  --sentinel-every-frames 16 --sentinel-burst-frames 3 \
  --sentinel-max-inferences 48
```

The timestamps above illustrate explicit per-generation assumptions; supply the coordinates
of the intended recording. Receive time never substitutes for capture time. A binding is
required for every reserved generation, in order, even if native acquisition ends before using
the final reservation. Only bindings for connections actually started enter the final analysis.

The preview does not inspect files, clocks, models or the camera. It includes the complete
ordinary capture preview, all effective analysis ceilings and the outer `approval_digest`.
Repeat the same command with `--approve` set to that **outer** digest. The nested capture or
analysis-template digest cannot authorize the combined operation.

Approved execution validates physical path separation, reads the bounded pinned package,
compiles the native model and validates the selected detection contract before camera contact.
It rechecks path admission after compilation. A wrong digest or unavailable model cannot leave
an archive, create a deployment, or contact the camera.

The ordinary capture options still control native reconnect policy, network time, source bytes,
per-generation frames, framing work, recoverable originals and optional storage-only grace.
There is one literal route, explicit generations, and no credentials, DNS, redirects or TLS.
The existing ordinary capture command retains its original approval and JSONL behavior.

## Interpret the output and continue after interruption

Save all complete stdout JSONL independently. Native capture rows retain
`fss.http_reconnect_capture.v1`; the combined operation uses `fss.http_capture_sentinel.v1`.
Output acceptance alone is not an external durable checkpoint acknowledgement.

| Parent row | Meaning |
| --- | --- |
| `capture_ready` | Exact model and selected contract are validated; camera contact has not begun. |
| `history_ready` | The typed capture receipt has a fully durable, released ended-history inventory. Includes its exact pin and `offline_sentinel_argv`. |
| `capture_incomplete` | No consumable settled history covers the entire started acquisition. Preserve native history/prefix/recovery rows; no automatic analysis begins. |
| `completed` | Complete native history analysis plus per-generation retained replay argv and measured analysis work/I/O. |
| `analysis_failed` | Exact history remains available for offline continuation; earlier imports or retained reports may also be durable. |

`history_ready.detail.capture_request_satisfied` is separate from custody. If the capture
request failed, the command returns failure without running perception. Its offline argv omit
`--approve-import`, and `requires_new_approval` is true. A separately reviewed offline invocation
can analyze the usable originals while preserving their source failure.

For a satisfied capture, `offline_sentinel_argv` includes the exact native offline approval.
If later import, decode, inference, retention or output fails, use those saved arguments with
`fss-sentinel-http-history`. The argv array preserves literal arguments, including paths with
spaces; it is not a shell program. The native owners verify exact roots and reuse existing
immutable publications on retry.

Never rerun live capture to repair analysis. An existing archive path refuses before camera
contact, including after a perfectly completed prior run. If no complete continuation row was
saved, retain the complete original capture rows and recover explicitly from their exact pins.
Neither the command nor its continuation discovers a latest root or grants camera reacquisition.

Each retained result in `completed.detail.native_sentinel_reruns` supplies an `argv` array
beginning with `fss-infer sentinel-replay`. Replay verifies the retained package, native recipe,
source closure and exact numerical report. It works from the deployment after the loose model
and original capture archive go offline. It remains a distinct bounded read/replay operation.

## Resource and interpretation boundaries

The whole history uses one inference allowance and shared source, pixel, JPEG, detection-head
and native-report pools. Complete bursts are allocated round-robin across actual recordings;
empty, failed, too-short and budget-skipped generations remain in the report. Native tracking
does not cross bursts or reconnect boundaries. All source imports precede model execution and
all computations precede retention. Current original custody, destination media and privacy
are rechecked before the complete report is released, including unsampled recordings.

The analysis frame/read/byte ceilings must cover the approved capture reservations. Capture's
`--timeout-ms`, `--max-framing-work` and `--max-report-bytes` remain capture-specific. The
combined command uses `--analysis-timeout-ms`, `--analysis-framing-work` and
`--analysis-report-bytes` for analysis, and `--analysis-work` for its shared model/preflight/
history/import work. Other detector and history bounds match `fss-sentinel-http-history`.

The analysis clock starts before model preflight and keeps running across capture. Checks occur
at native phase and I/O boundaries; a single native decode, inference, retention or acquisition
operation is not forcibly preempted. Acquisition retains its own separately approved deadline
and storage grace. Archive opening and subsequent analysis reads share one byte/operation
account. Destination custody keeps the native publication owner's existing limits; this is not
a whole-process destination-I/O meter.

Model proposals and class scores remain uncalibrated. This command neither publishes events
nor dispatches alerts. Unsampled time, a model returning no proposals, or an interrupted source
does not certify absence or continuous scene coverage. The loopback contracts exercise native
custody, replay and failure semantics; they do not establish physical-camera interoperability
or detector quality.
