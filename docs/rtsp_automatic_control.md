# Automatic AVC control under input backpressure

Reference implementation, 2026-10-15. Native compilation and regression execution for this
increment remain pending; committed tests and a queued workflow are not passing evidence.
No release, camera-compatibility or continuity claim is upgraded here.

## Affected paths

The same private pure sequencer now drives `AutomaticAvcConnection`,
`AutomaticAvcRecording`, and `AutomaticLiveAvcArchive`. `SupervisedAvcConnection`
inherits the connection fix without changing its retry classification, generation or
aggregate reservation contracts. The explicitly driven capture CLI and HEVC drivers are
not replaced by this sequencer.

The original failure was a control/input dependency: an accepted DESCRIBE could schedule
SETUP while exact-frame intake retained a coalesced or partial suffix. Request preparation
correctly refused with nonterminal backpressure. Repeating the same preparation on every
poll never advanced the native input owner which could clear or reject that suffix.

## Progress and ownership

An **unsent intent** is distinct from a prepared request. Safe protocol backpressure
keeps that intent but directs the next call into the existing native poll. Source, control,
media, failure and retirement outputs remain visible to the caller unchanged. Complete
semantic progress can make the intent eligible again. Successful queue admission removes
it; it never becomes an automatic replay of a prepared or partially sent request.

`Pending` does not prove the wire owner is empty: an incomplete exact frame also returns
it. Neither that wait nor a raw newly accepted chunk re-arms preparation. This preserves
fixed input deadlines and avoids repeatedly requesting credentials on a silent socket.
Clock-regression refusals preserve the intent, native ownership and current drain mode.
EOF, fatal failure, retirement and cancellation clear the intent.

For the protected archive, storage readiness is independent of protocol readiness. Recovery,
pin waits, checkpoint publication and catalog work still precede network intake. A storage
progress event cannot erase or re-arm a deferred protocol command. Cancellation and live
revocation retain their original classifications and ownership transfers. The manual
checkpoint owner and its write-ahead state machine are unchanged.

## Direct native checks

Use the repository-pinned toolchain and dependency closure:

```sh
bash scripts/bootstrap_toolchain.sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib rtsp::live_avc::automatic
cargo +nightly-2026-08-31 test --no-fail-fast --locked --offline -p fss-reference \
  --test automatic_control_backpressure --test automatic_archive_control_backpressure
cargo +nightly-2026-08-31 test --no-fail-fast --locked --offline -p fss-reference \
  --test automatic_live_archive_contract --test rtsp_payload_selection_streaming
```

`automatic/control.rs` contains six pure sequencing cases and is compiled privately by both
owning paths, so its unit cases appear in both module namespaces in an unfiltered run.
The seven connection/recording integration cases exercise both public APIs. Three archive
integration cases cover storage progress during deferred input, invalid suffix retirement,
and revocation/cancellation without publication. Fixtures contact loopback only.

The supplementary `Automatic RTSP control regressions` workflow executes these commands.
Repository-owned qualification and retained DSR receipts remain release authority. The
editing environment has no Rust toolchain and cannot resolve GitHub for a local checkout;
formatting, native execution, full manifest reconciliation and release qualification have
not been asserted. Preserve any failing native result rather than weakening a check.

## Remaining scope

No multi-camera supervisor was added in this increment. No new credential backend,
reconnection policy, media format, archive schema, retention policy or public effect
capability was introduced. Source retention, explicit picture timing and durable
publication remain duties of the existing authorized owners.
