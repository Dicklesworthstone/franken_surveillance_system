# Explicit storage-only grace after HTTP capture timeout

Status: implementation, **not qualified**. Rust compilation and regression execution
were not available in the implementation environment. This document does not upgrade a release,
physical-camera, coverage or end-to-end capture claim.

## Failure domain and scope

`fss-capture-reconnect` can hold a successfully received original HTTP read when the owner network
lease expires. The normal command uses that same deadline for storage admission. Its failure
report preserves the expected pin and the unpublished byte count, but in-memory input does not
survive process retirement. A recovery key cannot recreate bytes that were never staged.

An operator can now explicitly reserve a finite **storage-only** grace period:

```text
--recoverable yes --storage-drain-ms 1000
```

Use these options alongside the existing owner-authorized capture plan, preview it, and execute
only with the resulting exact approval digest. A nonzero grace requires lossless recovery-key
output. The default is `0`; the hard ceiling is `60000` milliseconds. Values must be unsigned
integers. Repeating the option, passing an out-of-range value, or omitting `--recoverable yes`
when grace is nonzero is rejected before capture I/O.

The maximum storage deadline is the original owner-clock start plus `--timeout-ms` plus the
approved grace. It is **not** measured from a later timeout, write, retry or output acknowledgement.
Every addition is checked. The network and decode deadline remains exactly `--timeout-ms`.
There is no permission to reconnect, parse expired input, disclose pixels, change retention or
extend any source, framing, history, step, byte or transcript allowance.

## Execution and refusal behavior

The capture driver passes the same `Owner` as network authority. Only storage cancellation checks
use the separately approved deadline. At expiry, the existing native reconnect state machine
observes its actual expired clock, retires its socket and retains the accepted read. The original
`HttpReconnectRecording::commit_wire` path can then publish that exact input under current storage
authority, without acknowledging it to the parser. Its `wire_durable` row has
`parser_acknowledged: null` for the retired source.

The grace is neither a retry policy nor an automatic repair loop. All work continues through the
existing bounded recorder and publisher, using their original budgets. Failure to accept a
prepared output row still prevents publication. A write/flush failure still poisons the transcript;
no recovery or terminal row is appended to that sink. Owner cancellation, a missing storage
capability, an unrepresentable clock, an expired storage lease, exhausted work or refused storage
remains a hard stop. Source bytes or roots left indeterminate are reported using the existing
pending-pin and unpublished-byte semantics; no new data is inferred or reacquired.

A wait that reaches the network deadline can return control to the recorder while storage grace
remains. It does not sleep through or renew the grace. The native recorder then performs its
existing terminal transition under its unchanged network authority and step ceiling.

When `--durable-history yes` is also approved, the same grace can cover the existing closed-source
history publication and verification barrier. History work remains its independent, whole-run
allowance. A storage failure can leave an exact prepared history pin rather than a durable root;
the driver does not convert that ambiguity into a completion claim.

## Machine and approval compatibility

The existing `fss.http_reconnect_capture.v1` output receives an optional `storage_drain` object only
for nonzero grace. It reports the maximum extra storage nanoseconds and unchanged network deadline,
with `network_extended`, `decode_extended` and `budgets_refilled` all false. The preview additionally
reports `recovery_key_required: true`. These are constraints on execution, not proof that salvage
occurred. Actual retained and unpublished bytes remain in the existing counters and source pins.

Zero grace uses the original admission path and leaves the legacy preview and approval bytes
unchanged, including existing decode, recovery and durable-history extensions. Nonzero grace adds
one named `storage_only_grace_ns` bound to the existing canonical plan's length-prefixed numeric
list. Its name binds storage-only semantics and its value binds the exact non-renewing grace;
the existing registered approval domains and recovery/history wrappers are retained. No new digest
domain or publication schema is introduced. A saved approval for a different grace is stale and
cannot start the clock, create an archive or contact the peer.

A timed-out capture stays unsuccessful even when all accepted bytes become durable:
`request_satisfied` remains false, and `unpublished_received_bytes` can become zero. Neither the
grace nor a successful write implies EOF, scene absence, physical capture continuity or crash
resume. Saving JSONL is still the operator's responsibility; `flush` is not external durability.

## Regression coverage added

`driver_drain_tests.rs` adds thirteen test functions covering default compatibility, option bounds,
recovery-key requirements, approval invalidation before I/O, exact prepared-read deadline cuts,
retired input publication without parsing or a second connection, optional history closure,
absolute storage expiry, poisoned output, network/decode/wait separation, every required storage
capability, persistent/transient clock failure, overflow refusal and successful multi-generation capture within shared bounds.
The native loopback cases reuse the repository's controlled clock and joined peer fixture.
They force expiry while acknowledging `wire_prepared`, rather than racing wall-clock sleeps.
Cold inspection verifies retained source through the exact recovery key and checks that an
idempotent recovery creates no additional root.

These tests have been **written, not executed**. Required native validation remains:

```sh
cargo test -p fss-cli --bin fss-capture-reconnect driver::drain_tests
cargo test -p fss-cli --bin fss-capture-reconnect
cargo test -p fss-reference http_reconnect
cargo fmt --all -- --check
cargo clippy -p fss-cli --all-targets -- -D warnings
scripts/qualify.sh
```

Do not weaken a qualification lane or substitute patch-application checks for Rust execution.

The integration preserves the later verified-frame-count postcondition: retaining timed-out wire
bytes does not satisfy an unmet `--stop-after-frames` target or overwrite a prior native refusal.
