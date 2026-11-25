# Live visual-degradation screening

The daemon can withhold usable camera coverage when decoded images show persistent
darkness, extreme brightness, exact repetition, or contrast collapse. Source recording
continues while the screen withholds perception and corroboration. This implements
the live admission part of NS-3 / INV-016 using the existing fixed policy.

## Enable the policy

Select the policy explicitly when starting either daemon entrypoint:

```sh
fss-daemon run --manifest site.json --sensor-health conservative-v1
fss site run --manifest site.json --sensor-health conservative-v1
```

Library callers set `DaemonStartConfig.sensor_health_policy` to
`Some(SensorHealthPolicy::ConservativeV1)`. Omitting the selection retains the existing
source-continuity policy. Unknown names are rejected; thresholds cannot be silently
changed through this option. The selection is fixed for the daemon process.

## Measurements

The screen uses complete decoded luma, independently of the detector model, its
weights, and its inference schedule. Immutable policy bytes and a digest bind the
thresholds:

| Finding | Required observations in one continuous source generation |
| --- | --- |
| Persistent dark field | At least 99.5% of luma samples are at most 20, for three consecutive frames |
| Persistent bright field | At least 99.5% of luma samples are at least 235, for three consecutive frames |
| Exact frame repetition | Eight distinct source positions have exactly identical decoded luma |
| Contrast collapse | After a 95th-minus-5th-percentile span of at least 32, three consecutive frames have a span of at most 2 |

These findings indicate suspected degradation. A legitimate static scene can repeat,
and a dark scene can be legitimate. This screen does not diagnose tampering,
obstruction, or camera failure. A clear result does not prove physical visibility,
calibration quality, or the absence of a person or event.

## Coverage, perception, and recovery

With the policy enabled, startup begins in `warming`. Eight fresh, successive clear
measurements release this screen's hold. The daemon must also establish independent
source continuity as described in
[DAEMON_ACQUISITION_READINESS.md](DAEMON_ACQUISITION_READINESS.md).

A finding or refused measurement moves the screen to `held`. The daemon publishes
`NotObservable` coverage and `Degraded` liveness, records a health conflict, and clears
the affected camera's motion baseline and pending corroboration observations. Other
cameras retain their observations. A held source cannot supply new perception frames
or an operator-triggered detection probe.

Recording and source handoff continue. The screen does not discard encoded source
frames, substitute pixels, or rewrite the evidence bytes to look healthy.

Recovery requires eight fresh clear observations. A recovery cutoff prevents older
buffered frames from re-entering cognition afterward. A reconnect, source gap, ring
shedding, or generation change resets temporal comparisons. A terminal event in the
same poll prevents a transient `Covered` publication. Multiple health transitions
within a poll retain separate ordered receipts; a clear boundary alone cannot publish
usable coverage before the final continuity decision.

`CameraRuntimeView.sensor_health` exposes the policy, `warming` / `held` / `clear`
state, recovery progress, observation and sample counters, latest observation digest,
findings, and refusal reason. It contains no image pixels.

## Durable evidence and bounded work

Coverage and liveness transitions retain a canonical receipt in the same publication
as both state changes. Each delta's `witness_digest` points to the exact receipt bytes.
Receipts bind policy, sensor and stream identity, stream generation, source sequence
and digest, capture bounds, dimensions, screen state, and the successful measurement
or explicit refusal reason. They also record that clearing the visual hold still
requires independent source continuity.

Receipt metadata survives restart and projection rebuild. Empty receipts and receipts
larger than 64 KiB are rejected before publication. Existing storage authority owns
publication; the visual screen creates no independent effect authority.

The live adapter retains only the preceding measurement and a monotonic source
position. Streaks survive tick boundaries without exhausting a finite retained-range
frame budget. Exact immediate retries are idempotent but pay validation cost; stale
positions and changed generations are refused.

Pixel shape, the configured dimensions, and the existing 4,194,304-sample limit are
checked before luma scratch allocation. The daemon also rejects dimensions above
4096 on either axis. Existing process authority is checked before measurement and
during row processing. Observations and work remain bounded per call.

## Regression coverage

Focused daemon tests cover visual holds, fresh recovery, source custody, generation
changes, malformed input, explicit opt-in, burst transitions, and receipt durability.
The sequential screen tests cover long-running bounded state, exact retries, stale
sources, and charged cancellation work. Run the daemon contract entrypoint with:

```sh
bash scripts/check_daemon_contracts.sh
```

Check the session handoff for actual native validation results. These contracts do
not establish optical qualification against every camera or physical scene.
