# Whole-run budgets for native AVC supervision

The owner-driven `SupervisedAvcConnection` and `SupervisedAvcRecording` APIs now
reserve native resources across reconnects. These are reference library APIs,
not a new daemon, camera qualification, or replacement for the existing
`fss-capture-rtsp reconnect` command.

## Two independent bounds

`ReconnectPolicy` bounds the total attempt count, absolute lifetime, scheduler
steps and exponential backoff. `ReconnectBudget` independently bounds the sum
of admitted native receive bytes, send bytes, socket calls and connection-driver
steps. The existing per-connection limits still apply inside each native owner.

A complete proposed connection must fit every resource dimension before its
attempt ordinal is admitted or a socket can open. Reservation is atomic: a late
component failure cannot debit earlier components. Overflow refuses instead of
wrapping or saturating the declared total.

The original `new` constructors remain available. Their first admitted native
profile establishes a checked aggregate equal to its resource maxima multiplied
by `max_attempts`. Before that first admission, the aggregate is unknown, not
unlimited. `new_with_budget` establishes an independently chosen whole-run ceiling
at construction. Neither constructor performs network I/O or grants authority.

```rust
use fss_reference::rtsp::live_avc::LiveAvcConfig;
use fss_reference::rtsp::live_avc::recording::LiveRecordingConfig;
use fss_reference::rtsp::live_avc::automatic::reconnect::{
    ReconnectBudget, ReconnectPolicy,
};
use fss_reference::rtsp::live_avc::automatic::reconnect::recording::
    SupervisedAvcRecording;

fn bounded_recording(
    config: &LiveAvcConfig,
    recording: LiveRecordingConfig,
    now: u64,
) -> Result<SupervisedAvcRecording, Box<dyn std::error::Error>> {
    // Three attempt slots, but only two full-profile allocations in total.
    let budget = ReconnectBudget::for_attempts(config.transport, config.max_steps, 2)?;
    let policy = ReconnectPolicy {
        max_attempts: 3,
        initial_backoff_ns: 250_000_000,
        max_backoff_ns: 5_000_000_000,
        deadline_ns: config.deadline_ns,
        max_steps: 100_000,
    };
    Ok(SupervisedAvcRecording::new_with_budget(
        config.binding.clone(), recording, policy, budget, now,
    )?)
}
```

Connecting and polling still require the exact live `TcpAuthority`. Each new
stream generation needs its own valid binding, and every recording attempt needs
an explicit source scope. The supervisor does not infer capture time, adopt an
old clock, or replay a previous prepared request.

## Reservations are not observed use

`resource_budget()` returns a read-only snapshot with `limit()`, `reserved()`,
`remaining()` and `admitted_attempts()`. The snapshot contains admitted maxima,
not measured traffic, CPU use, stored media size or durable publication receipts.
Observed TCP totals remain on the original native owner and its retirement.

The reference policy deliberately never refunds a reservation. A failed native
connect, EOF, acknowledgement, cancellation or revoked lease cannot replenish
capacity. This is conservative: an early failed connection can consume its full
allocation despite transferring little or no data. Reclaiming capacity would
require a separate trustworthy settlement contract and is not implemented here.

A resource refusal returns `ReconnectRefusal::Resources` with a typed component
and cause. It opens no socket, consumes no attempt ordinal, leaves reservations
unchanged and does not install the first profile. The normal scheduler admission
still consumes a scheduler step and enforces live time/authority. A caller can
correct a proposal with explicitly smaller native transport/work allowances;
the supervisor never silently rewrites them to make the attempt fit.

## A retry is not a configuration rollout

The first admitted profile pins the complete AVC receive configuration, including
reordering, NAL reconstruction, syntax and picture assembly. A subsequent attempt
cannot change those semantics, even by lowering a media limit. It also cannot
change the presentation, realm or authentication policy, or increase the original
native transport/work ceilings. A new configuration needs a new supervision grant.

The recording template separately fixes sensor/stream identity, payload type,
media tick rate and collection limits. EOF must pass through the existing recording
drain before retirement acknowledgement can schedule another attempt. All returned
windows, source omissions and terminal work remain owned by the caller. Budget
exhaustion never retracts an already returned recording or proves an absence.

## Validation boundary

The focused local command is:

```sh
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --lib rtsp::live_avc::automatic -- --nocapture
```

New contracts cover component-wise atomic refusal, checked aggregate arithmetic,
pre-connect refusal and correction through both public supervisors, immutable media
profiles, cancellation/revocation accounting, and real short-I/O AVC negotiation,
picture timing and EOF draining before a new-generation budget decision. The
source-bearing loopback tests retain the original prepared window across both a
refused second socket and an admitted fresh DESCRIBE.

These tests were added but compiler execution and test success have not yet been
confirmed for this increment. The queued supplementary GitHub workflow is not
release authority. No bead is closed or production/camera qualification claimed.
Storage/publication budgets, measured resource settlement, cold supervisor resume,
HEVC supervision and deployment-wide scheduling remain separate work.
