# Camera acquisition readiness

The daemon keeps transport acceptance, observed frames, and observed continuity
separate. Successful driver connection starts the existing `connecting` state,
with `NotObservable` coverage and unknown liveness.

## Establishing continuity

A camera becomes ready after two contiguous admitted frames from its current
sensor, stream, and generation. The first usable frame is reported as a separate
observation while coverage remains unobservable.

Frames are rejected before ring admission if their sensor or generation is wrong,
their stream identity changes within a generation, their sequence is zero or does
not increase, or their host receive timestamp is before session acceptance,
regresses, lies in the future, or is older than the configured stall timeout.

An accepted connection without usable frames remains subject to the stall timeout
and bounded reconnect backoff. A reconnect starts a fresh generation and must
establish continuity again; connection count alone cannot establish readiness.

## Losing and recovering readiness

An explicit source discontinuity, skipped source sequence, excessive time between
observations, or bounded-ring shedding invalidates readiness. Ring shedding resets
the retained continuity count while preserving the source sequence, identity, and
receive-time high-water. Two later retained samples are required after shedding.

The supervisor collects a camera's poll outcomes before publishing recovery. A
later disconnect or shedding in the same poll suppresses a transient recovery
claim. A source gap followed by valid continuity can publish the observed loss
and subsequent recovery.

Recovery uses a bounded point at the actual observation timestamp. It does not
backdate coverage across the preceding blind interval. This is acquisition
readiness, not a complete persisted gap-interval model. Calibration, image
quality, privacy, model operating envelope, and query coverage retain their own
requirements; these witnesses alone do not establish event absence.

## Regression checks

```sh
bash scripts/check_daemon_contracts.sh
```

The deterministic readiness contracts cover accepted idle sessions, first-frame
and second-frame behavior, reconnects, invalid identity/order/timestamps, source
gaps, same-poll disconnects, ring shedding, and attempted replay after shedding.
Existing supervisor and replay/soak tests also exercise the updated readiness
boundary. Local DSR qualification remains authoritative for deployment claims.
