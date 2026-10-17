# Bounded reconnect after interrupted RTSP capture

`fss-capture-rtsp reconnect --retry-interrupted yes` can start the next approved,
independent AVC or HEVC attempt after an abrupt socket read failure, but only once
the native capture owner has finished publishing its verified nonempty prefix.
The option belongs to the reconnect plan, not the single-capture plan.

Add `--retry-interrupted yes` to the complete existing reconnect command, preview
without `--approve`, then repeat with that preview's outer approval digest.
Keep the other source, timing, codec, credential, destination and budget options
unchanged. The preview enumerates all possible attempts and their aggregate
ceilings. A previous reconnect approval or an individual child approval cannot
authorize the additional retry policy. Omitting the option retains the previous
approval encoding, preview fields and retry behavior.

## Admission and failure semantics

Only native `Read` I/O failures classified as `ConnectionReset`,
`ConnectionAborted`, `BrokenPipe`, `UnexpectedEof` or `NotConnected` qualify for
consideration. Error messages are not parsed. Write failures, arbitrary protocol
faults, read timeouts, authentication failures, revoked authority, exhausted
budgets and output failures do not become retryable.

The native owner must close the failed socket and replay-verify the existing
original source, close presentation timing, publish every collected picture and
its catalog, and produce the final archive snapshot. The controller refuses a
successor when picture/index accounting disagrees, a candidate or unpublished
work remains, a remote request is unresolved, or untimed/unsealed pictures remain.
An empty reset cannot qualify. Recovery remains an explicit offline operation.

The interrupted attempt retains `ERR-CAPTURE-RTSP-SOURCE-001` and `complete:false`.
Only the enclosing reconnect report may emit
`retry_reason:"read_interrupted_after_verified_drain"` and `retrying:true`.
The native terminal report is flushed before the successor starts. Keep it: raw
wire, incomplete receiver state and source remainders are not claimed as durable
pictures or silently reconstructed. A preserved prefix is not successful capture,
source EOF, camera health, absence evidence or continuity across the interruption.

Retries consume only the already-enumerated attempts and capped backoff. Each
attempt keeps its own generation, receive/decode clocks, journal and new output
directories. Existing archives are neither overwritten nor merged. Ordinary
reconnect stops successfully if a later attempt reaches its approved target;
`--continue-after-success yes` instead requires every planned attempt to succeed,
so a later success cannot erase the earlier interrupted campaign failure.

Repeat `--retry-interrupted yes` unchanged with the original options when using
`--recover yes` or `--recover index`. Those operations need their own new approval;
recovery does not authorize a live connection or new recording epoch.

## Validation boundary

The implementation adds 16 capture-binary regression tests and five Linux
real-socket tests. Every new process test exercises both AVC and HEVC. An owned
loopback camera waits for the native collected-picture report before inducing an
abortive TCP close; no guessed reset delay or fabricated native outcome is used.
The tests cover reset then success, omitted opt-in, unresolved keepalive control,
campaign failure retention and repeated resets exhausting exactly two attempts.
After the process exits, every published original window is reopened and verified
from its separate archive, including picture count and retained source bytes.

Validation against the complete source tree of `52fa3d2c` passed all 218 selected
tests: 187 capture-binary unit tests and 31 duration, interruption, reconnect,
progress and reset process tests. The verified source archive plus the committed
feature reproduced Git tree `8dedc56f9bd799bce98b35d54d34230fd8b3298c` exactly
before adding the new process tests. This supersedes the initial test run using
an older dependency snapshot. The compiler was pinned `nightly-2026-08-31`;
Cargo resolution was locked and offline, with debug assertions enabled.

```sh
cargo test --locked --offline -p fss-cli --bin fss-capture-rtsp \
  --test capture_rtsp_interruption_reconnect_cli \
  --test capture_rtsp_reconnect_cli --test capture_rtsp_reset_cli \
  --test capture_rtsp_interruption_cli --test capture_rtsp_progress_cli \
  --test capture_rtsp_duration_cli -- --test-threads=1
```

These are native software contracts, not physical-camera, continuous-recording,
crash-resume or release qualification. The repository qualifier remains the
qualification entrypoint; passing selected tests does not waive any of its gates.
