# Explicit fixed-cadence reordered RTSP capture

`fss-capture-rtsp` can now retain AVC and HEVC pictures whose RTP presentation
order differs from decoding order. This advances the RTP/media timing slice of
FSS-048; it is not physical camera qualification or a recovered capture clock.

## Opt-in operator contract

Add `--max-reorder-pictures N`, where `N` is in `1..=16`, to an otherwise complete
capture plan. Continue to supply `--frame-duration-ticks` and `--timing-evidence`.
The operator asserts a fixed 90,000 Hz media cadence and a closed-IDR presentation
sequence. No packet header, decoder, model, or arrival-time observation supplies
that authority. The no-approval invocation remains pure and prices the effective
bound in its preview. Execute only after reviewing its new approval digest.

For example, with `--frame-duration-ticks 3600 --max-reorder-pictures 2`, decoding
positions `0, 1, 2, 3` may carry presentation positions `0, 3, 1, 2`. Their DTS
values are `0, 3600, 7200, 10800`, and their signed composition offsets are
`0, 7200, -3600, -3600`. Original pictures and RTP datagrams stay in decoding/source
order; the implementation does not sort, duplicate, interpolate or conceal them.
The existing recording muxers retain those signed offsets. `picture_collected`
JSONL rows report the actual offset, not an unconditional zero.

Omission or explicit `--max-reorder-pictures 0` keeps the previous monotonic
cadence policy, preview, approval and decode-clock encoding unchanged. A nonzero
bound changes both the approval and decode-clock identity; changing its value
requires a new approval. Plain capture, progress supervision and reconnect use the
same native options. Every reconnect attempt gets a new source generation and
clock; the bound is priced and included in each child plan. It is not a shared
mutable clock or a relaxation of any receive, work, storage or output allowance.

## Timing and completion rules

The public allocation-free `fss_packet::cadence::ReorderedRtpClock` owns a bounded
presentation-position bitmap. It validates timestamps against the declared
cadence around the current decode position using explicit modulo-32-bit RTP
arithmetic, while checking the full DTS and PTS sample intervals in `u64`.
Negative composition offsets are preserved. Every refusal is atomic.

The first actual IDR anchors presentation. Earlier non-IDR pictures use only the
collector's existing unselected startup path. Later IDRs must begin the next
closed presentation prefix; they cannot reset the clock or erase missing slots.
Local recording-window cuts do not reset the timing owner. Variable frame rates,
open GOPs, cadence drift, timestamps outside the bound, duplicated presentation
positions, unrepresentable intervals and changed stream identities are refused.
The native packet/codec owners can refuse malformed input before timing; their
original source failure is not replaced by a fabricated timing result.

A requested picture stop must close all presentation positions. A target inside
an unresolved group fails with `ERR-CAPTURE-RTSP-TIMING-001`; the driver does not
exceed the approved target to fill the group. Choose a source-compatible stop
boundary. An activity-progress stall is also checked before explicit sealing.

A source EOF may already have published a source-closed recording prefix under
the existing journal protocol. Final capture classification still rejects any
unresolved presentation position as a permanent timing failure, not a retryable
source shortfall. Previously returned roots, original datagrams, omissions and
recovery witnesses are preserved. A closed but shorter-than-requested EOF prefix
keeps the original incomplete-source classification and does not become success.
Neither EOF nor a timing bitmap certifies camera coverage or physical absence.
HEVC still needs a real source syntax boundary for its final selected picture;
neither the RTP marker nor socket EOF is upgraded into one.

## Executed validation

Local execution uses the checksum-verified complete `070282d7e71a0b22513f53d901809cd98ee4505d`
source archive and pinned `nightly-2026-08-31` compiler plus the exact cadence and
operator changes. New tests include twelve packet-clock tests (one enumerates
20,160 permutation/depth combinations), three CLI timing unit tests, and eight
real-process planning/capture/reconnect contracts. The process tests use committed
AVC `m_b_cavlc.h264` and HEVC `b_qcif_nopyramid_ref1.h265` B-picture fixtures with
independently specified presentation positions, short native reads, RTP rollover,
original archive custody, import and cold native pixel decode after the capture
archive is made unavailable. No foreign media application runs in production or
tests. The owned HEVC fixture sends an explicit EOS NAL to close its final picture.

The selected packet suite passed 208 tests. The capture-command unit suite passed
106 tests, and its real-process integration suite passed 33 tests, totaling 347
distinct passing tests including all 23 new tests across both increments. Changed
Rust files pass the pinned formatter. Targeted CLI Clippy (`--bin fss-capture-rtsp
--test capture_rtsp_cli --no-deps`) exits zero with existing warnings; dependencies
and the whole workspace are not claimed lint-clean. This is not validation of later
concurrent changes on `main`, all codecs/profiles, native platforms, DSR or release gates.

Reproduce with the repository-pinned toolchain:

```sh
cargo test --locked --offline -p fss-packet
cargo test --locked --offline -p fss-cli --bin fss-capture-rtsp --test capture_rtsp_cli
```

General presentation-clock recovery, variable cadence, open-GOP handling, physical
capture-time calibration and wider platform/camera qualification remain separate
work. No bead is closed by this implementation slice.
